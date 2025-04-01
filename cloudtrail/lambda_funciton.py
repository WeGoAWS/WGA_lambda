# lambda_functions/cloudtrail/lambda_function.py
import json
import os
import time
import boto3
from boto3.dynamodb.conditions import Key

# DynamoDB 테이블 설정
SESSIONS_TABLE = os.environ.get('SESSIONS_TABLE', 'Sessions')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

# Cognito 설정
COGNITO_DOMAIN = os.environ.get('COGNITO_DOMAIN')
COGNITO_IDENTITY_POOL_ID = os.environ.get('COGNITO_IDENTITY_POOL_ID')

# DynamoDB 클라이언트 초기화
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sessions_table = dynamodb.Table(SESSIONS_TABLE)

def lambda_handler(event, context):
    """
    Lambda 핸들러 함수
    """
    print(f"Received event: {json.dumps(event)}")
    
    # API Gateway에서 요청 경로 및 HTTP 메서드 추출
    path = event.get('path', '/')
    http_method = event.get('httpMethod', 'GET')
    
    # 엔드포인트 라우팅
    if path == '/cloudtrail/logs' and http_method == 'GET':
        return get_cloudtrail_logs(event)
    elif path == '/cloudtrail/analyze-logs' and http_method == 'GET':
        return analyze_cloudtrail_logs(event)
    else:
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'Not Found'})
        }

def get_cloudtrail_logs(event):
    """
    로그인한 사용자의 인증 정보를 이용하여 AWS 임시 자격 증명을 받고,
    CloudTrail의 lookup_events API를 통해 로그 이벤트를 수집합니다.
    """
    try:
        # 쿼리 파라미터에서 max_results 추출
        query_params = event.get('queryStringParameters', {}) or {}
        max_results = int(query_params.get('max_results', 50))
        
        # 세션에서 ID 토큰 가져오기
        id_token = get_id_token_from_session(event)
        if not id_token:
            return {
                'statusCode': 401,
                'body': json.dumps({"detail": "ID token not found."})
            }
        
        # 임시 AWS 세션 얻기
        session = get_aws_session(id_token)
        cloudtrail_client = session.client("cloudtrail")
        
        try:
            events_response = cloudtrail_client.lookup_events(MaxResults=max_results)
            events = events_response.get("Events", [])
        except Exception as e:
            return {
                'statusCode': 400,
                'body': json.dumps({"detail": f"CloudTrail lookup error: {str(e)}"})
            }
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({"CloudTrail_Events": events})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({"detail": f"Internal server error: {str(e)}"})
        }

def analyze_cloudtrail_logs(event):
    """
    분석 결과를 지정된 S3 버킷에 업로드합니다.
    """
    try:
        # 세션에서 ID 토큰 가져오기
        id_token = get_id_token_from_session(event)
        if not id_token:
            return {
                'statusCode': 401,
                'body': json.dumps({"detail": "ID token not found."})
            }

        # cloudtrail 추적이 활성화된 s3 버킷 리스트
        s3_buckets = get_active_cloudtrail_s3_buckets(id_token)

        # 로그 분석 진행 및 결과 S3 업로드
        try:
            # 실제 구현에서는 aws_log_processor.py 모듈의 process_logs 함수를 호출
            # 여기서는 간단한 모의 결과를 반환합니다
            result = {
                "message": "Analysis started",
                "buckets": s3_buckets,
                "status": "processing"
            }
        except Exception as e:
            return {
                'statusCode': 400,
                'body': json.dumps({"detail": f"로그 분석 실패: {str(e)}"})
            }
            
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(result)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({"detail": f"Internal server error: {str(e)}"})
        }

def get_id_token_from_session(event):
    """
    요청의 세션 쿠키에서 ID 토큰을 추출합니다.
    """
    # 쿠키에서 세션 ID 추출
    cookies = event.get('headers', {}).get('Cookie', '')
    session_id = extract_session_id_from_cookies(cookies)
    
    if not session_id:
        return None
    
    # 세션 정보 조회
    try:
        response = sessions_table.get_item(Key={'session_id': session_id})
        session = response.get('Item')
        
        # 세션 만료 확인
        if session and session.get('expiration', 0) < int(time.time()):
            return None
        
        return session.get('id_token') if session else None
    except Exception as e:
        print(f"Error retrieving session: {e}")
        return None

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

def get_aws_session(id_token):
    """
    ID 토큰을 사용하여 AWS 임시 세션을 생성합니다.
    """
    login_provider = COGNITO_DOMAIN.removeprefix("https://")
    cognito_identity = boto3.client("cognito-identity", region_name=AWS_REGION)
    
    try:
        # Cognito ID 얻기
        identity_response = cognito_identity.get_id(
            IdentityPoolId=COGNITO_IDENTITY_POOL_ID,
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
        
        # AWS 세션 생성
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretKey"],
            aws_session_token=creds["SessionToken"],
            region_name=AWS_REGION,
        )
        return session
    except Exception as e:
        print(f"Error creating AWS session: {e}")
        raise

def get_active_cloudtrail_s3_buckets(id_token):
    """
    CloudTrail이 활성화된 S3 버킷 목록을 가져옵니다.
    """
    session = get_aws_session(id_token)
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