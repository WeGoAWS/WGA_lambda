# lambda_functions/common/utils.py
import json
import boto3
import time
import os
from botocore.exceptions import ClientError
from common.config import CONFIG

def get_aws_session(id_token):
    """
    ID 토큰을 사용하여 AWS 임시 세션을 생성합니다.
    """
    cognito_domain = CONFIG['cognito']['domain']
    cognito_identity_pool_id = CONFIG['cognito']['identity_pool_id']
    
    login_provider = cognito_domain.removeprefix("https://")
    cognito_identity = boto3.client("cognito-identity", region_name=CONFIG['aws_region'])
    
    try:
        # Cognito ID 얻기
        identity_response = cognito_identity.get_id(
            IdentityPoolId=cognito_identity_pool_id,
            Logins={login_provider: id_token}
        )
        identity_id = identity_response.get("IdentityId")
        
        # 임시 자격 증명 얻기
        credentials_response = cognito_identity.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={login_provider: id_token}
        )
        creds = credentials_response.get("Credentials")
        
        if not creds:
            raise Exception("Failed to obtain temporary credentials.")
        
        # datetime 객체를 ISO 포맷 문자열로 변환
        if "Expiration" in creds and hasattr(creds["Expiration"], "isoformat"):
            creds["Expiration"] = creds["Expiration"].isoformat()
        
        # AWS 세션 생성
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretKey"],
            aws_session_token=creds["SessionToken"],
            region_name=CONFIG['aws_region'],
        )
        return session
    except Exception as e:
        print(f"Error creating AWS session: {e}")
        raise

def extract_session_id_from_cookies(cookies_string):
    """
    쿠키 문자열에서 세션 ID를 추출합니다.
    """
    if not cookies_string:
        return None
    
    cookies = {}
    for cookie in cookies_string.split(';'):
        if '=' in cookie:
            name, value = cookie.strip().split('=', 1)
            cookies[name] = value
    
    return cookies.get('session')

def format_api_response(status_code, body, headers=None):
    default_headers = {
        'Content-Type': 'application/json; charset=utf-8',  # charset 명시
        'Access-Control-Allow-Origin': 'http://localhost:5173',
        'Access-Control-Allow-Credentials': 'true'
    }
    
    if headers:
        default_headers.update(headers)
    
    response = {
        'statusCode': status_code,
        'headers': default_headers,
        # 핵심 수정: ensure_ascii=False 추가
        'body': json.dumps(body, ensure_ascii=False) if isinstance(body, (dict, list)) else str(body)
    }
    return response

def handle_api_exception(e, status_code=500):
    """
    API 예외를 처리합니다.
    """
    error_message = str(e)
    return format_api_response(
        status_code,
        {'error': error_message}
    )

def get_active_cloudtrail_s3_buckets(session):
    """
    CloudTrail이 활성화된 S3 버킷 목록을 가져옵니다.
    """
    cloudtrail_client = session.client("cloudtrail")

    try:
        trails = cloudtrail_client.describe_trails().get("trailList", [])
    except Exception as e:
        raise Exception(f"CloudTrail access error: {str(e)}")

    active_buckets = []
    for trail in trails:
        s3_bucket = trail.get("S3BucketName")
        if s3_bucket:
            try:
                # 각 트레일의 상태를 확인하여 로깅이 활성화되어 있는지 체크
                status = cloudtrail_client.get_trail_status(Name=trail.get("Name"))
                if status.get("IsLogging"):
                    active_buckets.append(s3_bucket)
            except Exception:
                # 개별 트레일 상태 조회 실패 시 해당 트레일은 건너뜁니다.
                continue

    return active_buckets

def upload_to_s3(session, bucket, key, data):
    """
    S3 버킷에 데이터를 업로드합니다.
    """
    try:
        s3_client = session.client('s3')
        
        # 문자열 또는 딕셔너리/리스트인 경우 JSON 문자열로 변환
        if isinstance(data, (dict, list)):
            data = json.dumps(data)
        
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=data
        )
        return True
    except ClientError as e:
        print(f"Error uploading to S3: {e.response['Error']['Message']}")
        return False

def download_from_s3(session, bucket, key):
    """
    S3 버킷에서 객체를 다운로드합니다.
    """
    try:
        s3_client = session.client('s3')
        response = s3_client.get_object(Bucket=bucket, Key=key)
        data = response['Body'].read()
        return data
    except ClientError as e:
        print(f"Error downloading from S3: {e.response['Error']['Message']}")
        return None

def get_latest_s3_object(session, bucket, prefix=''):
    """
    S3 버킷에서 지정된 접두사로 시작하는 최신 객체의 키를 가져옵니다.
    """
    try:
        s3_client = session.client('s3')
        response = s3_client.list_objects_v2(
            Bucket=bucket,
            Prefix=prefix
        )
        
        if 'Contents' not in response or not response['Contents']:
            return None
        
        # LastModified 기준으로 정렬하여 최신 파일 찾기
        latest_file = max(response['Contents'], key=lambda x: x['LastModified'])
        return latest_file['Key']
    except ClientError as e:
        print(f"Error listing S3 objects: {e.response['Error']['Message']}")
        return None