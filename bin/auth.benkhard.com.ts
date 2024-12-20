#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { AuthBenkhardComStack } from '../lib/auth.benkhard.com-stack';

const app = new cdk.App();
new AuthBenkhardComStack(app, 'AuthBenkhardComStack');