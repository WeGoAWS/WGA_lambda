# lambda_functions/policy_recommendation/lambda_function.py
import json
import os
import time
import boto3
import uuid
from boto3.dynamodb.conditions import Key

# DynamoDB 테이블 설정
SESSIONS_TABLE = os.environ.get('SESSIONS_TABLE', 'Sessions')
ANALYSIS_RESULTS_TABLE = os.environ.get('ANALYSIS_RESULTS_TABLE', 'AnalysisResults')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
OUTPUT_BUCKET = os.environ.get('OUTPUT_BUCKET', 'wga-outputbucket')

# DynamoDB 클라이언트 초기화
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sessions_table = dynamodb.Table(SESSIONS_TABLE)
analysis_results_table = dynamodb.Table(ANALYSIS_RESULTS_TABLE)

def lambda_handler(event, context):
    """
    Lambda 핸들러 함수
    """
    print(f"Received event: {json.dumps(event)}")
    
    # API Gateway에서 요청 경로 및 HTTP 메서드 추출
    path = event.get('path', '/')
    http_method = event.get('httpMethod', 'GET')
    
    # 엔드포인트 라우팅
    if path == '/policy-recommendation/process-multiple-analyses' and http_method == 'GET':
        return process_multiple_analyses(event)
    elif path == '/policy-recommendation/apply-policy-changes' and http_method == 'POST':
        return apply_policy_changes(event)
    else:
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'Not Found'})
        }

def process_multiple_analyses(event):
    """
    여러 분석 결과를 한 번에 처리합니다.
    S3 버킷 'wga-outputbucket'의 results 폴더에서 가장 최신 JSON 파일을 불러와서 처리합니다.
    """
    try:
        # 세션에서 ID 토큰 가져오기
        id_token = get_id_token_from_session(event)
        if not id_token:
            return {
                'statusCode': 401,
                'body': json.dumps({"detail": "인증이 필요합니다."})
            }
        
        # AWS 세션 생성
        session = get_aws_session(id_token)
        s3 = session.client("s3")
        bucket_name = OUTPUT_BUCKET
        prefix = "results/"

        try:
            response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        except Exception as e:
            return {
                'statusCode': 500,
                'body': json.dumps({"detail": f"S3 버킷 접근 중 오류 발생: {str(e)}"})
            }

        if 'Contents' not in response or not response['Contents']:
            return {
                'statusCode': 404,
                'body': json.dumps({"detail": "결과 파일이 존재하지 않습니다."})
            }

        # 최신 파일 선택 (LastModified 기준)
        latest_file = max(response['Contents'], key=lambda x: x['LastModified'])
        latest_key = latest_file['Key']

        try:
            obj = s3.get_object(Bucket=bucket_name, Key=latest_key)
            file_content = obj['Body'].read()
            analysis_results_data = json.loads(file_content)
        except Exception as e:
            return {
                'statusCode': 500,
                'body': json.dumps({"detail": f"파일 불러오기 실패: {str(e)}"})
            }

        processed_results = []
        
        # JSON 데이터가 리스트 형태일 경우 각 항목을 처리합니다.
        if isinstance(analysis_results_data, list):
            for result in analysis_results_data:
                processed_result = {
                    "date": result.get("date"),
                    "user": result.get("user"),
                    "log_count": result.get("log_count"),
                    "analysis_timestamp": result.get("analysis_timestamp"),
                    "analysis_comment": result.get("analysis_comment"),
                    "risk_level": result.get("risk_level"),
                    "policy_recommendation": result.get("policy_recommendation"),
                    "type": result.get("type")  # daily_global_summary 등 추가 정보가 있을 수 있음
                }
                
                # DynamoDB에 결과 저장
                store_analysis_result(processed_result)
                
                processed_results.append(processed_result)
        else:
            # JSON 데이터 구조가 예상과 다른 경우 예외 처리합니다.
            return {
                'statusCode': 400,
                'body': json.dumps({"detail": "JSON 구조가 예상과 다릅니다."})
            }

        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(processed_results)
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({"detail": f"Internal server error: {str(e)}"})
        }

def apply_policy_changes(event):
    """
    사용자가 선택한 권한 변경 사항들을 실제 IAM 정책에 적용합니다.
    """
    try:
        # 세션에서 ID 토큰 가져오기
        id_token = get_id_token_from_session(event)
        if not id_token:
            return {
                'statusCode': 401,
                'body': json.dumps({"detail": "인증이 필요합니다."})
            }
        
        # 요청 바디 파싱
        body = json.loads(event.get('body', '{}'))
        updates = body
        
        # AWS 세션 생성
        session = get_aws_session(id_token)
        iam_client = session.client("iam")
        
        overall_results = []
        
        for update in updates:
            result = {
                "user": None,
                "added_permissions": [],
                "removed_permissions": [],
                "errors": []
            }
            
            user_arn = update.get("user_arn")
            if not user_arn:
                overall_results.append({
                    "status": "error",
                    "message": "사용자 ARN이 누락되었습니다.",
                    "details": result
                })
                continue
                
            if ":user/" in user_arn:
                user_name = user_arn.split("/")[-1]
                result["user"] = user_name
            elif ":assumed-role/" in user_arn:
                overall_results.append({
                    "status": "error",
                    "message": "역할(Role) 권한은 현재 수정할 수 없습니다. IAM 사용자(User)만 지원됩니다.",
                    "details": {"user": user_arn}
                })
                continue
            else:
                overall_results.append({
                    "status": "error",
                    "message": f"지원되지 않는 ARN 형식입니다: {user_arn}",
                    "details": {"user": user_arn}
                })
                continue
            
            add_permissions = [item.get("action") for item in update.get("add_permissions", []) if item.get("apply")]
            remove_permissions = [item.get("action") for item in update.get("remove_permissions", []) if item.get("apply")]
            
            if not add_permissions and not remove_permissions:
                overall_results.append({
                    "status": "info",
                    "message": "적용할 변경 사항이 없습니다.",
                    "details": result
                })
                continue
            
            try:
                policy_names = iam_client.list_user_policies(UserName=user_name).get("PolicyNames", [])
                wga_policy_name = "WGALogAnalysisInlinePolicy"
                if wga_policy_name in policy_names:
                    policy_response = iam_client.get_user_policy(
                        UserName=user_name,
                        PolicyName=wga_policy_name
                    )
                    policy_document = policy_response.get("PolicyDocument", {})
                else:
                    policy_document = {
                        "Version": "2012-10-17",
                        "Statement": []
                    }
                
                if add_permissions:
                    allow_stmt = None
                    for stmt in policy_document.get("Statement", []):
                        if stmt.get("Effect") == "Allow":
                            allow_stmt = stmt
                            break
                    
                    if not allow_stmt:
                        allow_stmt = {
                            "Effect": "Allow",
                            "Action": [],
                            "Resource": "*"
                        }
                        policy_document["Statement"].append(allow_stmt)
                    
                    if "Action" not in allow_stmt:
                        allow_stmt["Action"] = []
                    
                    if isinstance(allow_stmt["Action"], str):
                        allow_stmt["Action"] = [allow_stmt["Action"]]
                    
                    for permission in add_permissions:
                        if permission not in allow_stmt["Action"]:
                            allow_stmt["Action"].append(permission)
                            result["added_permissions"].append(permission)
                
                if remove_permissions:
                    for stmt in policy_document.get("Statement", []):
                        if stmt.get("Effect") == "Allow" and "Action" in stmt:
                            if isinstance(stmt["Action"], str):
                                if stmt["Action"] in remove_permissions:
                                    result["removed_permissions"].append(stmt["Action"])
                                    # 문자열 형태일 경우 빈 문자열로 설정
                                    stmt["Action"] = ""
                            elif isinstance(stmt["Action"], list):
                                for permission in remove_permissions:
                                    if permission in stmt["Action"]:
                                        stmt["Action"].remove(permission)
                                        result["removed_permissions"].append(permission)

                # 삭제 후, "Action" 필드가 빈 리스트이거나 빈 문자열인 statement를 제거
                policy_document["Statement"] = [
                    stmt for stmt in policy_document.get("Statement", [])
                    if (
                        (isinstance(stmt.get("Action"), list) and len(stmt.get("Action")) > 0)
                        or (isinstance(stmt.get("Action"), str) and stmt.get("Action").strip() != "")
                    )
                ]
                
                if not policy_document["Statement"]:
                    # 모든 statement가 제거되었으므로, 인라인 정책을 삭제
                    iam_client.delete_user_policy(
                        UserName=user_name,
                        PolicyName=wga_policy_name
                    )
                else:
                    iam_client.put_user_policy(
                        UserName=user_name,
                        PolicyName=wga_policy_name,
                        PolicyDocument=json.dumps(policy_document)
                    )
                
                overall_results.append({
                    "status": "success",
                    "message": "IAM 정책이 성공적으로 업데이트되었습니다.",
                    "details": result
                })
                
            except Exception as e:
                result["errors"].append(str(e))
                overall_results.append({
                    "status": "error",
                    "message": f"IAM 정책 업데이트 중 오류가 발생했습니다: {str(e)}",
                    "details": result
                })
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(overall_results)
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
    cognito_domain = os.environ.get('COGNITO_DOMAIN')
    cognito_identity_pool_id = os.environ.get('COGNITO_IDENTITY_POOL_ID')
    
    login_provider = cognito_domain.removeprefix("https://")
    cognito_identity = boto3.client("cognito-identity", region_name=AWS_REGION)
    
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

def store_analysis_result(result):
    """
    분석 결과를 DynamoDB에 저장합니다.
    """
    try:
        # UUID 생성
        result_id = str(uuid.uuid4())
        
        # 저장할 데이터 준비
        item = {
            "id": result_id,
            "date": result.get("date"),
            "user_arn": result.get("user"),
            "log_count": result.get("log_count"),
            "analysis_timestamp": result.get("analysis_timestamp"),
            "analysis_comment": result.get("analysis_comment"),
            "risk_level": result.get("risk_level"),
            "policy_recommendation": result.get("policy_recommendation", {}),
            "created_at": int(time.time())
        }
        
        if result.get("type"):
            item["type"] = result.get("type")
        
        # DynamoDB에 저장
        analysis_results_table.put_item(Item=item)
        
        return result_id
    except Exception as e:
        print(f"Error storing analysis result: {e}")
        raise