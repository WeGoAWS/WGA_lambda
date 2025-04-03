# lambda_functions/auth/lambda_function.py
import json
import os
import time
from common.db import create_session, delete_session, create_or_update_user
from common.config import CONFIG
from common.utils import extract_session_id_from_cookies, format_api_response, handle_api_exception
from auth_service import verify_cognito_token, create_user_session, logout_user, validate_and_create_session

def lambda_handler(event, context):
    """
    Lambda 핸들러 함수
    """
    print(f"Received event: {json.dumps(event)}")
    
    # API Gateway에서 요청 경로 및 HTTP 메서드 추출
    path = event.get('path', '/')
    http_method = event.get('httpMethod', 'GET')
    
    # 엔드포인트 라우팅
    try:
        if path == '/auth' and http_method == 'GET':
            return index(event)
        elif path == '/auth/logout' and http_method == 'GET':
            return logout(event)
        elif path == '/auth/verify-token' and http_method == 'POST':
            return verify_token(event)
        else:
            return format_api_response(404, {'error': 'Not Found'})
    except Exception as e:
        return handle_api_exception(e)

def index(event):
    """
    현재 로그인 상태에 따라 사용자 정보를 반환하거나 로그인 안내 메시지를 출력합니다.
    """
    # 쿠키에서 세션 ID 추출
    cookies = event.get('headers', {}).get('Cookie', '')
    session_id = extract_session_id_from_cookies(cookies)
    
    if not session_id:
        return format_api_response(200, {"message": "Hello, please login!"})
    
    # 세션 정보 조회 (common.db에서 가져오는 대신 auth_service의 함수 사용 가능)
    from common.db import get_session
    session_info = get_session(session_id)
    if not session_info:
        return format_api_response(200, {"message": "Hello, please login!"})
    
    provider = session_info.get('provider', 'unknown')
    
    return format_api_response(200, {"message": f"Logged in with {provider}"})

def logout(event):
    """
    사용자 로그아웃 처리. 세션 정보를 제거합니다.
    """
    # 쿠키에서 세션 ID 추출
    cookies = event.get('headers', {}).get('Cookie', '')
    session_id = extract_session_id_from_cookies(cookies)
    
    if session_id:
        # auth_service의 logout_user 함수 활용
        logout_user(session_id)
    
    # 세션 쿠키 삭제를 위한 응답 헤더 설정
    return format_api_response(
        302, 
        '',
        {
            'Location': '/auth/',
            'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0'
        }
    )

def verify_token(event):
    """
    프론트엔드에서 받은 토큰을 검증하고 유효한 경우 세션에 저장합니다.
    """
    try:
        # 요청 바디 파싱
        body = json.loads(event.get('body', '{}'))
        provider = body.get('provider', '')
        id_token = body.get('id_token', '')
        access_token = body.get('access_token', '')
        refresh_token = body.get('refresh_token', '')
        
        if not id_token or provider not in ["cognito", "google", "azure"]:
            return format_api_response(400, {"detail": "Invalid token data or unsupported provider"})
        
        # auth_service의 래퍼 함수 활용
        success, session_id, claims, error_msg = validate_and_create_session(
            provider, id_token, access_token, refresh_token
        )
        
        if not success:
            return format_api_response(401, {"detail": error_msg})
        
        # 제로 트러스트 컨텍스트 평가 추가
        context = {
            'source_ip': event.get('requestContext', {}).get('identity', {}).get('sourceIp', ''),
            'user_agent': event.get('headers', {}).get('User-Agent', ''),
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'mfa_used': body.get('mfa_used', False)
        }
        
        # 제로 트러스트 평가 Lambda 호출
        try:
            lambda_client = session.client('lambda')
            
            payload = {
                'body': json.dumps({
                    'user_arn': claims.get('sub'),
                    'action': 'sts:AssumeRole',  # 예시 액션
                    'resource': '*',
                    'context': context
                })
            }
            
            response = lambda_client.invoke(
                FunctionName=f'wga-zero-trust-enforcer-{CONFIG["env"]}',
                InvocationType='RequestResponse',
                Payload=json.dumps(payload)
            )
            
            # 응답 처리
            if response.get('StatusCode') == 200:
                zt_result = json.loads(response.get('Payload').read())
                zt_body = json.loads(zt_result.get('body', '{}'))
                
                # 접근 거부 결정인 경우
                if zt_body.get('decision') == 'deny':
                    return format_api_response(403, {
                        "detail": "Zero Trust policy denied access",
                        "risk_score": zt_body.get('risk_score'),
                        "factors": zt_body.get('factors')
                    })
                
                # MFA 필요 결정인 경우
                if zt_body.get('decision') == 'require_mfa' and not context.get('mfa_used'):
                    return format_api_response(401, {
                        "detail": "Additional authentication required",
                        "require_mfa": True,
                        "risk_score": zt_body.get('risk_score')
                    })
                
                # 세션 만료 시간을 제로 트러스트 평가 결과에 따라 조정
                if zt_body.get('expires_at'):
                    expiration = zt_body.get('expires_at') - int(time.time())
                else:
                    expiration = claims.get("exp") - int(time.time())
        except Exception as e:
            print(f"Zero Trust evaluation error (proceeding with default policy): {e}")
            expiration = claims.get("exp") - int(time.time())
        
        # 세션 쿠키 설정
        return format_api_response(
            200, 
            {"status": "success", "message": "Token verified successfully"},
            {
                'Set-Cookie': f'session={session_id}; HttpOnly; Path=/; Max-Age={claims.get("exp") - int(time.time())}'
            }
        )
    except Exception as e:
        return handle_api_exception(e)