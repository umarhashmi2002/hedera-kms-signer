#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { HederaKmsSignerStack } from '../lib/hedera-kms-signer-stack';

const app = new cdk.App();

new HederaKmsSignerStack(app, 'HederaKmsSignerStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
  },
  hederaNetwork: app.node.tryGetContext('hederaNetwork') ?? 'testnet',
  hederaOperatorId: app.node.tryGetContext('hederaOperatorId') ?? '0.0.8291501',
  alertEmail: app.node.tryGetContext('alertEmail') ?? 'admin@example.com',
});
