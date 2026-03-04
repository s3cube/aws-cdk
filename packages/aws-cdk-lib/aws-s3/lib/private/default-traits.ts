import type { IConstruct } from 'constructs';
import type {
  AddToResourcePolicyResult,
  GrantOnKeyResult,
  IEncryptedResource,
  IEncryptedResourceFactory,
  IGrantable,
  IResourcePolicyFactory,
  IResourceWithPolicyV2,
  PolicyStatement,
} from '../../../aws-iam';
import { DefaultEncryptedResourceFactories, DefaultPolicyFactories } from '../../../aws-iam';
import type { CfnKey } from '../../../aws-kms';
import { KeyGrants } from '../../../aws-kms';
import type { CfnResource, ResourceEnvironment } from '../../../core';
import { Reference, Tokenization, ValidationError } from '../../../core';
import { findClosestRelatedResource, findL1FromRef } from '../../../core/lib/helpers-internal';
import { BucketPolicyStatements } from '../mixins/bucket-policy';
import type { IBucketRef } from '../s3.generated';
import { CfnBucket, CfnBucketPolicy } from '../s3.generated';

/**
 * Factory to create an encrypted resource for a Bucket.
 */
class EncryptedBucketFactory implements IEncryptedResourceFactory {
  public forResource(resource: CfnResource): IEncryptedResource {
    return ifCfnBucket(resource, (r) => new EncryptedCfnBucket(r));
  }
}

class EncryptedCfnBucket implements IEncryptedResource {
  public readonly env: ResourceEnvironment;

  constructor(private readonly bucket: CfnBucket) {
    this.env = bucket.env;
  }

  public grantOnKey(grantee: IGrantable, ...actions: string[]): GrantOnKeyResult {
    const key = tryFindKmsKeyforBucket(this.bucket);
    return {
      grant: key ? KeyGrants.fromKey(key).actions(grantee, ...actions) : undefined,
    };
  }
}

/**
 * Factory to create a resource policy for a Bucket.
 */
class BucketWithPolicyFactory implements IResourcePolicyFactory {
  public forResource(resource: CfnResource): IResourceWithPolicyV2 {
    return ifCfnBucket(resource, (r) => new CfnBucketWithPolicy(r));
  }
}

class CfnBucketWithPolicy implements IResourceWithPolicyV2 {
  public readonly env: ResourceEnvironment;
  private policy?: CfnBucketPolicy;

  constructor(private readonly bucket: CfnBucket) {
    this.env = bucket.env;
  }

  public addToResourcePolicy(statement: PolicyStatement): AddToResourcePolicyResult {
    if (!this.policy) {
      this.policy = tryFindBucketPolicyForBucket(this.bucket) ?? new CfnBucketPolicy(this.bucket, 'S3BucketPolicy', {
        bucket: this.bucket.ref,
        policyDocument: { Statement: [] },
      });
    }

    this.policy.with(new BucketPolicyStatements([statement]));

    return { statementAdded: true, policyDependable: this.policy };
  }
}

function ifCfnBucket<A>(resource: IConstruct, factory: (r: CfnBucket) => A): A {
  if (!CfnBucket.isCfnBucket(resource)) {
    throw new ValidationError(`Construct ${resource.node.path} is not of type CfnBucket`, resource);
  }

  return factory(resource);
}

function tryFindKmsKeyforBucket(bucket: IBucketRef): CfnKey | undefined {
  const cfnBucket = tryFindBucketConstruct(bucket);
  const kmsMasterKeyId = cfnBucket && Array.isArray((cfnBucket.bucketEncryption as
      CfnBucket.BucketEncryptionProperty)?.serverSideEncryptionConfiguration) ?
    (((cfnBucket.bucketEncryption as CfnBucket.BucketEncryptionProperty).serverSideEncryptionConfiguration as
          CfnBucket.ServerSideEncryptionRuleProperty[])[0]?.serverSideEncryptionByDefault as
          CfnBucket.ServerSideEncryptionByDefaultProperty)?.kmsMasterKeyId
    : undefined;
  if (!kmsMasterKeyId) {
    return undefined;
  }
  return findClosestRelatedResource<IConstruct, CfnKey>(
    bucket,
    'AWS::KMS::Key',
    (_, key) => key.ref === kmsMasterKeyId || key.attrKeyId === kmsMasterKeyId || key.attrArn === kmsMasterKeyId,
  );
}

function tryFindBucketConstruct(bucket: IBucketRef): CfnBucket | undefined {
  return findL1FromRef<IBucketRef, CfnBucket>(
    bucket,
    'AWS::S3::Bucket',
    (cfn, ref) => ref.bucketRef == cfn.bucketRef,
  );
}

/**
 * Attempts to find an existing bucket policy for the specified S3 bucket.
 * Finds the closest matching policy to the specified bucket.
 *
 * @param bucket - The S3 bucket reference to search for an associated bucket policy
 * @returns The bucket policy if found, undefined otherwise
 */
function tryFindBucketPolicyForBucket(bucket: IBucketRef): CfnBucketPolicy | undefined {
  return findClosestRelatedResource<IBucketRef, CfnBucketPolicy>(
    bucket,
    'AWS::S3::BucketPolicy',
    (b: any, policy) => {
      const reversed = Tokenization.reverse(policy.bucket) || policy.bucket;
      if (Reference.isReference(reversed)) {
        if (b === reversed.target) {
          return true;
        }
      }
      const possibleRefs = new Set([b.ref, b.bucketName, b.bucketArn, b.bucketRef?.bucketName, b.bucketRef?.bucketArn].filter(Boolean));
      return possibleRefs.has(reversed) || String(reversed).includes(b.node.id);
    },
  );
}

DefaultEncryptedResourceFactories.set('AWS::S3::Bucket', new EncryptedBucketFactory());
DefaultPolicyFactories.set('AWS::S3::Bucket', new BucketWithPolicyFactory());
