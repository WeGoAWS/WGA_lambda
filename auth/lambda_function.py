# lambda_functions/auth/lambda_function.py
import json
import os
import time
import urllib.request
import boto3
from boto3.dynamodb.conditions import Key
import uuid
from jose import jwk, jwt
from jose.utils import base64url_decode

# DynamoDB 테이블 설정
SESSIONS_TABLE = os.environ.get('SESSIONS_TABLE', 'Sessions')
USERS_TABLE = os.environ.get('USERS_TABLE', 'Users')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

# Cognito 설정
USER_POOL_ID = os.environ.get('USER_POOL_ID')
COGNITO_CLIENT_ID = os.environ.get('COGNITO_CLIENT_ID')
COGNITO_DOMAIN = os.environ.get('COGNITO_DOMAIN')

# DynamoDB 클라이언트 초기화
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
sessions_table = dynamodb.Table(SESSIONS_TABLE)
users_table = dynamodb.Table(USERS_TABLE)

def lambda_handler(event, context):
    """
    Lambda 핸들러 함수
    """
    print(f"Received event: {json.dumps(event)}")
    
    # API Gateway에서 요청 경로 및 HTTP 메서드 추출
    path = event.get('path', '/')
    http_method = event.get('httpMethod', 'GET')
    
    # 엔드포인트 라우팅
    if path == '/auth' and http_method == 'GET':
        return index(event)
    elif path == '/auth/logout' and http_method == 'GET':
        return logout(event)
    elif path == '/auth/verify-token' and http_method == 'POST':
        return verify_token(event)
    else:
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'Not Found'})
        }

def index(event):
    """
    현재 로그인 상태에 따라 사용자 정보를 반환하거나 로그인 안내 메시지를 출력합니다.
    """
    # 쿠키에서 세션 ID 추출
    cookies = event.get('headers', {}).get('Cookie', '')
    session_id = extract_session_id_from_cookies(cookies)
    
    if not session_id:
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({"message": "Hello, please login!"})
        }
    
    # 세션 정보 조회
    session_info = get_session(session_id)
    if not session_info:
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({"message": "Hello, please login!"})
        }
    
    provider = session_info.get('provider', 'unknown')
    
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({"message": f"Logged in with {provider}"})
    }

def logout(event):
    """
    사용자 로그아웃 처리. 세션 정보를 제거합니다.
    """
    # 쿠키에서 세션 ID 추출
    cookies = event.get('headers', {}).get('Cookie', '')
    session_id = extract_session_id_from_cookies(cookies)
    
    if session_id:
        # DynamoDB에서 세션 삭제
        try:
            sessions_table.delete_item(Key={'session_id': session_id})
        except Exception as e:
            print(f"Error deleting session: {e}")
    
    # 세션 쿠키 삭제를 위한 응답 헤더 설정
    return {
        'statusCode': 302,
        'headers': {
            'Location': '/auth/',
            'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0'
        },
        'body': ''
    }

def verify_token(event):
    """
    프론트엔드에서 받은 토큰을 검증하고 유효한 경우 세션에 저장합니다.
    """
    try:
        # 요청 바디 파싱
        body = json.loads(event.get('body', '{}'))
        provider = body.get('provider', '')
        id_token = body.get('id_token', '')
        
        if not id_token or provider not in ["cognito", "google", "azure"]:
            return {
                'statusCode': 400,
                'body': json.dumps({"detail": "Invalid token data or unsupported provider"})
            }
        
        # 토큰 검증 - AWS Cognito
        if provider == "cognito":
            # Cognito 사용자 풀 정보
            region = AWS_REGION
            user_pool_id = USER_POOL_ID
            client_id = COGNITO_CLIENT_ID
            
            # JWT 토큰 검증을 위한 공개키 가져오기
            keys_url = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json'
            
            try:
                with urllib.request.urlopen(keys_url) as f:
                    response = f.read()
                keys = json.loads(response.decode('utf-8'))['keys']
            except Exception as e:
                return {
                    'statusCode': 401,
                    'body': json.dumps({"detail": f'Failed to fetch JWKS: {str(e)}'})
                }
            
            # JWT 토큰 헤더 디코딩
            try:
                headers = jwt.get_unverified_headers(id_token)
                kid = headers['kid']
            except Exception as e:
                return {
                    'statusCode': 401,
                    'body': json.dumps({"detail": f'Invalid JWT headers: {str(e)}'})
                }
            
            # 검증할 키 찾기
            key_index = -1
            for i in range(len(keys)):
                if kid == keys[i]['kid']:
                    key_index = i
                    break
            
            if key_index == -1:
                return {
                    'statusCode': 401,
                    'body': json.dumps({"detail": 'Public key not found in jwks.json'})
                }
            
            # 공개키 가져오기
            try:
                public_key = jwk.construct(keys[key_index])
            except Exception as e:
                return {
                    'statusCode': 401,
                    'body': json.dumps({"detail": f'Failed to construct public key: {str(e)}'})
                }
            
            # 토큰 서명 검증
            try:
                message, encoded_signature = id_token.rsplit('.', 1)
                decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
                
                # 서명 검증 수행
                is_verified = public_key.verify(message.encode("utf8"), decoded_signature)
                
                if not is_verified:
                    return {
                        'statusCode': 401,
                        'body': json.dumps({"detail": 'Signature verification failed'})
                    }
            except Exception as e:
                return {
                    'statusCode': 401,
                    'body': json.dumps({"detail": f'Signature verification error: {str(e)}'})
                }
            
            # 클레임 검증
            try:
                claims = jwt.get_unverified_claims(id_token)
                
                # 만료 시간 확인
                current_time = time.time()
                expiration_time = claims['exp']
                
                if current_time > expiration_time:
                    return {
                        'statusCode': 401,
                        'body': json.dumps({"detail": 'Token is expired'})
                    }
                
                # 발행자 확인
                expected_issuer = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}'
                actual_issuer = claims['iss']
                
                if actual_issuer != expected_issuer:
                    return {
                        'statusCode': 401,
                        'body': json.dumps({"detail": 'Token was not issued by expected provider'})
                    }
                
                # 클라이언트 ID 확인
                if claims['aud'] != client_id and claims.get('client_id') != client_id:
                    return {
                        'statusCode': 401,
                        'body': json.dumps({"detail": 'Token was not issued for this client'})
                    }
                
            except KeyError as e:
                return {
                    'statusCode': 401,
                    'body': json.dumps({"detail": f'Missing required claim: {str(e)}'})
                }
            except Exception as e:
                return {
                    'statusCode': 401,
                    'body': json.dumps({"detail": f'Error validating claims: {str(e)}'})
                }
            
            # 검증 성공 시 세션 생성
            session_id = str(uuid.uuid4())
            
            # 세션 데이터 저장
            session_data = {
                'session_id': session_id,
                'id_token': id_token,
                'provider': provider,
                'user_sub': claims.get('sub'),
                'expiration': int(claims.get('exp')),
                'created_at': int(time.time())
            }
            
            try:
                # DynamoDB에 세션 정보 저장
                sessions_table.put_item(Item=session_data)
                
                # 사용자 정보 저장
                store_user_info(claims, provider)
                
                # 세션 쿠키 설정
                return {
                    'statusCode': 200,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Set-Cookie': f'session={session_id}; HttpOnly; Path=/; Max-Age={claims.get("exp") - int(time.time())}'
                    },
                    'body': json.dumps({"status": "success", "message": "Token verified successfully"})
                }
            except Exception as e:
                return {
                    'statusCode': 500,
                    'body': json.dumps({"detail": f'Error storing session: {str(e)}'})
                }
        
        # GCP 또는 Azure 토큰 검증 로직도 필요하다면 이곳에 추가
        
        return {
            'statusCode': 400,
            'body': json.dumps({"detail": "Unsupported provider"})
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({"detail": f"Internal server error: {str(e)}"})
        }

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

def get_session(session_id):
    """
    DynamoDB에서 세션 정보를 조회합니다.
    """
    if not session_id:
        return None
    
    try:
        response = sessions_table.get_item(Key={'session_id': session_id})
        session = response.get('Item')
        
        # 세션 만료 확인
        if session and session.get('expiration', 0) < int(time.time()):
            # 만료된 세션 삭제
            sessions_table.delete_item(Key={'session_id': session_id})
            return None
        
        return session
    except Exception as e:
        print(f"Error retrieving session: {e}")
        return None

def store_user_info(claims, provider):
    """
    사용자 정보를 DynamoDB에 저장합니다.
    """
    user_id = claims.get("sub")
    if not user_id:
        raise ValueError("Token claims에 'sub' 필드가 없습니다.")

    user_data = {
        "sub": user_id,
        "email": claims.get("email"),
        "issuer": claims.get("iss"),
        "provider": provider,
        "last_login": int(time.time())
    }

    try:
        # 기존 사용자 확인 후 업데이트 또는 삽입
        response = users_table.get_item(Key={"sub": user_id})
        if "Item" in response:
            # 사용자가 존재하면 업데이트
            users_table.update_item(
                Key={"sub": user_id},
                UpdateExpression="set email=:e, provider=:p, last_login=:l",
                ExpressionAttributeValues={
                    ":e": user_data["email"],
                    ":p": user_data["provider"],
                    ":l": user_data["last_login"]
                }
            )
        else:
            # 새 사용자 생성
            users_table.put_item(Item=user_data)
        
        return True
    except Exception as e:
        print(f"Error storing user info: {e}")
        return False