# lambda_functions/policy_recommendation/lambda_function.py
import json
import os
import time
import uuid
from common.db import get_session
from common.config import CONFIG
from common.utils import extract_session_id_from_cookies, format_api_response, handle_api_exception, get_aws_session
from recommendation_service import get_latest_analysis_from_s3, store_analysis_results, format_policy_recommendations, apply_policy_changes

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
        if path == '/policy-recommendation/process-multiple-analyses' and http_method == 'GET':
            return process_multiple_analyses(event)
        elif path == '/policy-recommendation/apply-policy-changes' and http_method == 'POST':
            return apply_policy_changes_handler(event)
        else:
            return format_api_response(404, {'error': 'Not Found'})
    except Exception as e:
        return handle_api_exception(e)

def process_multiple_analyses(event):
    """
    여러 분석 결과를 한 번에 처리합니다.
    """
    try:
        # 세션에서 ID 토큰 가져오기
        id_token = get_id_token_from_session(event)
        if not id_token:
            return format_api_response(401, {"detail": "인증이 필요합니다."})
        
        # AWS 세션 생성
        session = get_aws_session(id_token)
        
        # recommendation_service의 래퍼 함수 활용
        result = process_analysis_results_workflow(session)
        
        return format_api_response(200, result)
    except Exception as e:
        return handle_api_exception(e)

def apply_policy_changes_handler(event):
    """
    사용자가 선택한 권한 변경 사항들을 실제 IAM 정책에 적용합니다.
    """
    try:
        # 세션에서 ID 토큰 가져오기
        id_token = get_id_token_from_session(event)
        if not id_token:
            return format_api_response(401, {"detail": "인증이 필요합니다."})
        
        # 요청 바디 파싱
        body = json.loads(event.get('body', '{}'))
        updates = body
        
        # AWS 세션 생성
        session = get_aws_session(id_token)
        
        # recommendation_service의 래퍼 함수 활용
        result = apply_policy_changes_with_validation(session, updates)
        
        return format_api_response(200, result)
    except Exception as e:
        return handle_api_exception(e)

def get_id_token_from_session(event):
    """
    요청의 세션 쿠키에서 ID 토큰을 추출합니다.
    """
    # 쿠키에서 세션 ID 추출
    headers = event.get('headers', {})
    cookies = headers.get('Cookie', '') or headers.get('cookie', '')
    
    session_id = extract_session_id_from_cookies(cookies)
    
    if not session_id:
        return None
    
    # 세션 정보 조회
    session = get_session(session_id)
    
    # 세션에서 ID 토큰 반환
    id_token = session.get('id_token') if session else None
    
    return id_token