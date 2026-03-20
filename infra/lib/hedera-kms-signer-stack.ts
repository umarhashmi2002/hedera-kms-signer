import * as cdk from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as nodejs from 'aws-cdk-lib/aws-lambda-nodejs';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as apigwv2Integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as apigwv2Authorizers from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as snsSubscriptions from 'aws-cdk-lib/aws-sns-subscriptions';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import * as path from 'path';

export interface HederaKmsSignerStackProps extends cdk.StackProps {
  hederaNetwork: string;
  hederaOperatorId: string;
  alertEmail: string;
}

export class HederaKmsSignerStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: HederaKmsSignerStackProps) {
    super(scope, id, props);

    // ── KMS Signing Key (ECDSA secp256k1) ──
    const signingKey = new kms.Key(this, 'HederaSigningKey', {
      description: 'ECDSA secp256k1 signing key for Hedera transactions',
      keySpec: kms.KeySpec.ECC_SECG_P256K1,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      alias: 'hedera-signer-dev',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // ── DynamoDB Audit Table ──
    const auditTable = new dynamodb.Table(this, 'AuditTable', {
      tableName: 'hedera_signing_audit',
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'ttl',
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // ── Cognito User Pool ──
    const userPool = new cognito.UserPool(this, 'SignerUserPool', {
      userPoolName: 'hedera-signer-user-pool',
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      autoVerify: { email: true },
      passwordPolicy: {
        minLength: 12,
        requireUppercase: true,
        requireLowercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const userPoolClient = new cognito.UserPoolClient(this, 'SignerUserPoolClient', {
      userPool,
      userPoolClientName: 'hedera-signer-api-client',
      authFlows: {
        userPassword: true,
        userSrp: true,
      },
      generateSecret: false,
      accessTokenValidity: cdk.Duration.hours(1),
      idTokenValidity: cdk.Duration.hours(1),
      refreshTokenValidity: cdk.Duration.days(30),
    });

    // ── Lambda Function ──
    const lambdaDir = path.join(__dirname, '..', '..');  // points to hedera-kms-signer/

    const signingFunction = new nodejs.NodejsFunction(this, 'SigningFunction', {
      functionName: 'hedera-kms-signer',
      entry: path.join(lambdaDir, 'src', 'handler.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_20_X,
      memorySize: 256,
      timeout: cdk.Duration.seconds(60),
      environment: {
        KMS_KEY_ID: signingKey.keyId,
        AUDIT_TABLE_NAME: auditTable.tableName,
        HEDERA_NETWORK: props.hederaNetwork,
        HEDERA_OPERATOR_ID: props.hederaOperatorId,
        POLICY_MAX_AMOUNT_HBAR: '5',
        POLICY_ALLOWED_RECIPIENTS: '0.0.1234,0.0.5678',
        POLICY_ALLOWED_TRANSACTION_TYPES: 'CryptoTransfer',
        POLICY_ALLOWED_HOURS_START: '8',
        POLICY_ALLOWED_HOURS_END: '22',
      },
      bundling: {
        minify: true,
        target: 'es2022',
        format: nodejs.OutputFormat.ESM,
        mainFields: ['module', 'main'],
        externalModules: ['@aws-sdk/*'],
        banner: 'import { createRequire } from "module"; const require = createRequire(import.meta.url);',
        commandHooks: {
          beforeBundling(_inputDir: string, _outputDir: string) { return []; },
          beforeInstall(_inputDir: string, _outputDir: string) { return []; },
          afterBundling(_inputDir: string, outputDir: string) {
            const docsDir = path.join(lambdaDir, 'docs');
            return [`cp -r "${docsDir}" "${outputDir}/docs"`];
          },
        },
      },
    });

    // Grant least-privilege permissions
    signingKey.grant(signingFunction, 'kms:Sign', 'kms:GetPublicKey');
    auditTable.grant(signingFunction, 'dynamodb:PutItem', 'dynamodb:GetItem');

    // ── Log Group with 7-day retention ──
    new logs.LogGroup(this, 'SigningFunctionLogGroup', {
      logGroupName: `/aws/lambda/${signingFunction.functionName}`,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ── API Gateway HTTP API with Cognito JWT Auth ──
    const jwtAuthorizer = new apigwv2Authorizers.HttpJwtAuthorizer('CognitoAuthorizer', 
      `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}`, {
        jwtAudience: [userPoolClient.userPoolClientId],
        identitySource: ['$request.header.Authorization'],
      }
    );

    const httpApi = new apigwv2.HttpApi(this, 'SigningHttpApi', {
      apiName: 'hedera-signer-api',
      corsPreflight: {
        allowOrigins: ['*'],
        allowMethods: [apigwv2.CorsHttpMethod.GET, apigwv2.CorsHttpMethod.POST],
        allowHeaders: ['Authorization', 'Content-Type'],
      },
    });

    const lambdaIntegration = new apigwv2Integrations.HttpLambdaIntegration(
      'SigningLambdaIntegration', signingFunction
    );

    // POST /sign-transfer — authenticated
    httpApi.addRoutes({
      path: '/sign-transfer',
      methods: [apigwv2.HttpMethod.POST],
      integration: lambdaIntegration,
      authorizer: jwtAuthorizer,
    });

    // GET /public-key — authenticated
    httpApi.addRoutes({
      path: '/public-key',
      methods: [apigwv2.HttpMethod.GET],
      integration: lambdaIntegration,
      authorizer: jwtAuthorizer,
    });

    // GET /docs — public (no auth needed for API docs)
    httpApi.addRoutes({
      path: '/docs',
      methods: [apigwv2.HttpMethod.GET],
      integration: lambdaIntegration,
    });

    // POST /rotate-key — authenticated
    httpApi.addRoutes({
      path: '/rotate-key',
      methods: [apigwv2.HttpMethod.POST],
      integration: lambdaIntegration,
      authorizer: jwtAuthorizer,
    });

    // Add kms:CreateKey and kms:DisableKey permissions for key rotation
    signingFunction.addToRolePolicy(new iam.PolicyStatement({
      actions: ['kms:CreateKey', 'kms:DisableKey'],
      resources: ['*'],
    }));

    // Apply throttling via CfnStage override
    const defaultStage = httpApi.defaultStage?.node.defaultChild as apigwv2.CfnStage;
    if (defaultStage) {
      defaultStage.defaultRouteSettings = {
        throttlingBurstLimit: 50,
        throttlingRateLimit: 100,
      };
    }

    // ── SNS Topic for Alerts ──
    const alertTopic = new sns.Topic(this, 'AlertTopic', {
      topicName: 'hedera-signer-alerts',
    });
    alertTopic.addSubscription(new snsSubscriptions.EmailSubscription(props.alertEmail));

    // ── CloudWatch Alarms ──

    // Alarm: Lambda error rate > 5% over 5 minutes
    const errorAlarm = new cloudwatch.Alarm(this, 'LambdaErrorAlarm', {
      alarmName: 'hedera-signer-lambda-errors',
      metric: signingFunction.metricErrors({
        period: cdk.Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 5,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    errorAlarm.addAlarmAction(new cloudwatchActions.SnsAction(alertTopic));

    // Alarm: High denial rate (custom metric — Lambda publishes this)
    const denialMetric = new cloudwatch.Metric({
      namespace: 'HederaSigner',
      metricName: 'DeniedRequests',
      period: cdk.Duration.minutes(5),
      statistic: 'Sum',
    });
    const denialAlarm = new cloudwatch.Alarm(this, 'DenialRateAlarm', {
      alarmName: 'hedera-signer-denial-rate',
      metric: denialMetric,
      threshold: 10,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    denialAlarm.addAlarmAction(new cloudwatchActions.SnsAction(alertTopic));

    // ── CloudTrail (management events) ──
    const trailBucket = new s3.Bucket(this, 'CloudTrailBucket', {
      bucketName: `hedera-signer-cloudtrail-${this.account}-${this.region}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // CloudTrail log group for metric filters
    const trailLogGroup = new logs.LogGroup(this, 'CloudTrailLogGroup', {
      logGroupName: '/aws/cloudtrail/hedera-signer',
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    new cloudtrail.Trail(this, 'SignerTrail', {
      trailName: 'hedera-signer-trail',
      bucket: trailBucket,
      isMultiRegionTrail: false,
      includeGlobalServiceEvents: false,
      sendToCloudWatchLogs: true,
      cloudWatchLogGroup: trailLogGroup,
      cloudWatchLogsRetention: logs.RetentionDays.ONE_WEEK,
    });

    // ── Metric Filter: KMS calls by non-Lambda principal ──
    const nonLambdaKmsMetric = new logs.MetricFilter(this, 'NonLambdaKmsMetricFilter', {
      logGroup: trailLogGroup,
      filterPattern: logs.FilterPattern.all(
        logs.FilterPattern.stringValue('$.eventSource', '=', 'kms.amazonaws.com'),
        logs.FilterPattern.any(
          logs.FilterPattern.stringValue('$.eventName', '=', 'Sign'),
          logs.FilterPattern.stringValue('$.eventName', '=', 'GetPublicKey'),
        ),
        logs.FilterPattern.stringValue(
          '$.userIdentity.sessionContext.sessionIssuer.userName',
          '!=',
          signingFunction.role!.roleName,
        ),
      ),
      metricNamespace: 'HederaSigner',
      metricName: 'NonLambdaKmsCalls',
      metricValue: '1',
      defaultValue: 0,
    });

    // Alarm: KMS calls by non-Lambda principal
    const nonLambdaKmsAlarm = new cloudwatch.Alarm(this, 'NonLambdaKmsAlarm', {
      alarmName: 'hedera-signer-non-lambda-kms-usage',
      metric: nonLambdaKmsMetric.metric({
        period: cdk.Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 0,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    nonLambdaKmsAlarm.addAlarmAction(new cloudwatchActions.SnsAction(alertTopic));

    // ── Outputs ──
    new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: httpApi.apiEndpoint,
      description: 'HTTP API endpoint URL',
    });

    new cdk.CfnOutput(this, 'SigningFunctionArn', {
      value: signingFunction.functionArn,
      description: 'Signing Lambda function ARN',
    });

    new cdk.CfnOutput(this, 'KmsKeyArn', {
      value: signingKey.keyArn,
      description: 'KMS signing key ARN',
    });

    new cdk.CfnOutput(this, 'AuditTableName', {
      value: auditTable.tableName,
      description: 'DynamoDB audit table name',
    });

    new cdk.CfnOutput(this, 'UserPoolId', {
      value: userPool.userPoolId,
      description: 'Cognito User Pool ID',
    });

    new cdk.CfnOutput(this, 'UserPoolClientId', {
      value: userPoolClient.userPoolClientId,
      description: 'Cognito User Pool Client ID',
    });

    new cdk.CfnOutput(this, 'CognitoIssuerUrl', {
      value: `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}`,
      description: 'Cognito JWT Issuer URL (use for token validation)',
    });
  }
}
