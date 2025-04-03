# lambda_functions/common/db.py
import boto3
import time
import uuid
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

# 공통 설정 가져오기
from common.config import CONFIG

# DynamoDB 클라이언트 및 리소스 초기화
dynamodb = boto3.resource('dynamodb', region_name=CONFIG['aws_region'])
dynamodb_client = boto3.client('dynamodb', region_name=CONFIG['aws_region'])

# 테이블 객체 초기화
sessions_table = dynamodb.Table(CONFIG['tables']['sessions'])
users_table = dynamodb.Table(CONFIG['tables']['users'])
analysis_results_table = dynamodb.Table(CONFIG['tables']['analysis_results'])
user_behavior_profiles_table = dynamodb.Table(CONFIG['tables']['user_behavior_profiles'])
role_templates_table = dynamodb.Table(CONFIG['tables']['role_templates'])
role_history_table = dynamodb.Table(CONFIG['tables']['role_history'])
anomaly_events_table = dynamodb.Table(CONFIG['tables']['anomaly_events'])
access_decisions_table = dynamodb.Table(CONFIG['tables']['access_decisions'])

# 테이블 정의 - 전역 변수로 선언
TABLES_DEFINITION = [
    {
        'name': CONFIG['tables']['sessions'],
        'key_schema': [
            {'AttributeName': 'session_id', 'KeyType': 'HASH'}
        ],
        'attribute_definitions': [
            {'AttributeName': 'session_id', 'AttributeType': 'S'}
        ],
        'provisioned_throughput': {
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        },
        'ttl': {
            'AttributeName': 'expiration',
            'Enabled': True
        }
    },
    {
        'name': CONFIG['tables']['users'],
        'key_schema': [
            {'AttributeName': 'sub', 'KeyType': 'HASH'}
        ],
        'attribute_definitions': [
            {'AttributeName': 'sub', 'AttributeType': 'S'}
        ],
        'provisioned_throughput': {
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    },
    {
        'name': CONFIG['tables']['analysis_results'],
        'key_schema': [
            {'AttributeName': 'id', 'KeyType': 'HASH'}
        ],
        'attribute_definitions': [
            {'AttributeName': 'id', 'AttributeType': 'S'},
            {'AttributeName': 'user_arn', 'AttributeType': 'S'}
        ],
        'global_secondary_indexes': [
            {
                'IndexName': 'UserArnIndex',
                'KeySchema': [
                    {'AttributeName': 'user_arn', 'KeyType': 'HASH'}
                ],
                'Projection': {
                    'ProjectionType': 'ALL'
                },
                'ProvisionedThroughput': {
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            }
        ],
        'provisioned_throughput': {
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    },
    {
        'name': CONFIG['tables']['user_behavior_profiles'],
        'key_schema': [
            {'AttributeName': 'user_arn', 'KeyType': 'HASH'}
        ],
        'attribute_definitions': [
            {'AttributeName': 'user_arn', 'AttributeType': 'S'},
            {'AttributeName': 'risk_score', 'AttributeType': 'N'}
        ],
        'global_secondary_indexes': [
            {
                'IndexName': 'RiskScoreIndex',
                'KeySchema': [
                    {'AttributeName': 'risk_score', 'KeyType': 'HASH'}
                ],
                'Projection': {
                    'ProjectionType': 'ALL'
                },
                'ProvisionedThroughput': {
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            }
        ],
        'provisioned_throughput': {
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    }
]

# 사용자 행동 프로파일 관련 함수
def get_user_activity_profile(user_arn):
    """
    사용자 ARN으로 행동 프로파일을 조회합니다.
    """
    try:
        response = user_behavior_profiles_table.get_item(Key={'user_arn': user_arn})
        return response.get('Item')
    except ClientError as e:
        print(f"Error retrieving user profile: {e.response['Error']['Message']}")
        return None

def update_user_activity_profile(user_arn, profile_data):
    """
    사용자 행동 프로파일을 업데이트합니다.
    """
    try:
        profile_data['user_arn'] = user_arn
        user_behavior_profiles_table.put_item(Item=profile_data)
        return True
    except ClientError as e:
        print(f"Error updating user profile: {e.response['Error']['Message']}")
        return False

# 역할 템플릿 관련 함수
def get_role_template(template_id):
    """
    템플릿 ID로 역할 템플릿을 조회합니다.
    """
    try:
        response = role_templates_table.get_item(Key={'id': template_id})
        return response.get('Item')
    except ClientError as e:
        print(f"Error retrieving role template: {e.response['Error']['Message']}")
        return None

def get_templates_by_service(service_name):
    """
    특정 서비스와 관련된 역할 템플릿을 조회합니다.
    """
    try:
        response = role_templates_table.query(
            IndexName='ServiceIndex',
            KeyConditionExpression=Key('target_services').contains(service_name)
        )
        return response.get('Items', [])
    except ClientError as e:
        print(f"Error querying templates by service: {e.response['Error']['Message']}")
        return []

# 역할 이력 관련 함수
def save_role_history(history_data):
    """
    역할 변경 이력을 저장합니다.
    """
    try:
        role_history_table.put_item(Item=history_data)
        return history_data.get('id')
    except ClientError as e:
        print(f"Error saving role history: {e.response['Error']['Message']}")
        return None

def get_role_history_by_user(user_arn, limit=10):
    """
    사용자별 역할 변경 이력을 조회합니다.
    """
    try:
        response = role_history_table.query(
            IndexName='UserArnIndex',
            KeyConditionExpression=Key('user_arn').eq(user_arn),
            Limit=limit,
            ScanIndexForward=False
        )
        return response.get('Items', [])
    except ClientError as e:
        print(f"Error retrieving role history: {e.response['Error']['Message']}")
        return []

# 이상 이벤트 관련 함수
def save_anomaly_event(event_data):
    """
    이상 행동 이벤트를 저장합니다.
    """
    try:
        anomaly_events_table.put_item(Item=event_data)
        return event_data.get('id')
    except ClientError as e:
        print(f"Error saving anomaly event: {e.response['Error']['Message']}")
        return None

def get_anomaly_events_by_user(user_arn, limit=20):
    """
    사용자별 이상 행동 이벤트를 조회합니다.
    """
    try:
        response = anomaly_events_table.query(
            IndexName='UserArnIndex',
            KeyConditionExpression=Key('user_arn').eq(user_arn),
            Limit=limit,
            ScanIndexForward=False
        )
        return response.get('Items', [])
    except ClientError as e:
        print(f"Error retrieving anomaly events: {e.response['Error']['Message']}")
        return []

# 접근 결정 관련 함수
def save_access_decision(decision_data):
    """
    접근 결정 이력을 저장합니다.
    """
    try:
        access_decisions_table.put_item(Item=decision_data)
        return decision_data.get('request_id')
    except ClientError as e:
        print(f"Error saving access decision: {e.response['Error']['Message']}")
        return None

def get_access_decisions_by_user(user_arn, limit=20):
    """
    사용자별 접근 결정 이력을 조회합니다.
    """
    try:
        response = access_decisions_table.query(
            IndexName='UserArnIndex',
            KeyConditionExpression=Key('user_arn').eq(user_arn),
            Limit=limit,
            ScanIndexForward=False
        )
        return response.get('Items', [])
    except ClientError as e:
        print(f"Error retrieving access decisions: {e.response['Error']['Message']}")
        return []

# 세션 관련 함수
def get_session(session_id):
    """
    세션 ID로 세션 정보를 조회합니다.
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
    except ClientError as e:
        print(f"Error retrieving session: {e.response['Error']['Message']}")
        return None

def create_session(session_data):
    """
    새 세션을 생성합니다.
    """
    if not session_data.get('session_id'):
        session_data['session_id'] = str(uuid.uuid4())
    
    if not session_data.get('created_at'):
        session_data['created_at'] = int(time.time())
    
    try:
        sessions_table.put_item(Item=session_data)
        return session_data['session_id']
    except ClientError as e:
        print(f"Error creating session: {e.response['Error']['Message']}")
        return None

def delete_session(session_id):
    """
    세션을 삭제합니다.
    """
    try:
        sessions_table.delete_item(Key={'session_id': session_id})
        return True
    except ClientError as e:
        print(f"Error deleting session: {e.response['Error']['Message']}")
        return False

# 사용자 관련 함수
def get_user(sub):
    """
    Cognito 사용자 ID(sub)로 사용자 정보를 조회합니다.
    """
    try:
        response = users_table.get_item(Key={'sub': sub})
        return response.get('Item')
    except ClientError as e:
        print(f"Error retrieving user: {e.response['Error']['Message']}")
        return None

def create_or_update_user(user_data):
    """
    사용자 정보를 생성하거나 업데이트합니다.
    """
    sub = user_data.get('sub')
    if not sub:
        raise ValueError("사용자 ID(sub)가 누락되었습니다.")
    
    try:
        # 현재 시간 추가
        if 'last_login' not in user_data:
            user_data['last_login'] = int(time.time())
        
        # 기존 사용자 확인
        existing_user = get_user(sub)
        
        if existing_user:
            # 업데이트 표현식 생성
            update_expression = "set "
            expression_attribute_values = {}
            
            for key, value in user_data.items():
                if key != 'sub':  # 기본 키는 업데이트할 수 없음
                    update_expression += f"{key}=:{key}, "
                    expression_attribute_values[f":{key}"] = value
            
            # 마지막 쉼표 제거
            update_expression = update_expression.rstrip(", ")
            
            # 업데이트 실행
            users_table.update_item(
                Key={'sub': sub},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_attribute_values
            )
        else:
            # 신규 사용자 생성
            users_table.put_item(Item=user_data)
        
        return True
    except ClientError as e:
        print(f"Error creating/updating user: {e.response['Error']['Message']}")
        return False

# 분석 결과 관련 함수
def get_analysis_result(result_id):
    """
    분석 결과 ID로 결과를 조회합니다.
    """
    try:
        response = analysis_results_table.get_item(Key={'id': result_id})
        return response.get('Item')
    except ClientError as e:
        print(f"Error retrieving analysis result: {e.response['Error']['Message']}")
        return None

def create_analysis_result(result_data):
    """
    새 분석 결과를 생성합니다.
    """
    if not result_data.get('id'):
        result_data['id'] = str(uuid.uuid4())
    
    if not result_data.get('created_at'):
        result_data['created_at'] = int(time.time())
    
    try:
        analysis_results_table.put_item(Item=result_data)
        return result_data['id']
    except ClientError as e:
        print(f"Error creating analysis result: {e.response['Error']['Message']}")
        return None

def get_user_analysis_results(user_arn, limit=20):
    """
    특정 사용자의 분석 결과를 조회합니다.
    """
    try:
        response = analysis_results_table.query(
            IndexName='UserArnIndex',  # 보조 인덱스 (생성 필요)
            KeyConditionExpression=Key('user_arn').eq(user_arn),
            Limit=limit,
            ScanIndexForward=False  # 내림차순 정렬 (최신순)
        )
        return response.get('Items', [])
    except ClientError as e:
        print(f"Error querying user analysis results: {e.response['Error']['Message']}")
        return []

def get_latest_analysis_results(limit=20):
    """
    가장 최근의 분석 결과를 조회합니다.
    """
    try:
        # GSI가 없으므로 스캔 후 정렬
        response = analysis_results_table.scan(Limit=limit * 2)  # 제한보다 많이 가져와서 정렬
        
        items = response.get('Items', [])
        items.sort(key=lambda x: x.get('created_at', 0), reverse=True)
        
        return items[:limit]
    except ClientError as e:
        print(f"Error getting latest analysis results: {e.response['Error']['Message']}")
        return []

# DynamoDB 테이블 확인 및 생성
def ensure_tables_exist():
    """
    필요한 DynamoDB 테이블이 존재하는지 확인하고, 없으면 생성합니다.
    """
    try:
        # 기존 테이블 목록 조회
        existing_tables = dynamodb_client.list_tables()['TableNames']
        
        for table_def in TABLES_DEFINITION:
            table_name = table_def['name']
            
            if table_name not in existing_tables:
                print(f"테이블 생성 시작: {table_name}")
                
                # 테이블 생성 파라미터 구성
                params = {
                    'TableName': table_name,
                    'KeySchema': table_def['key_schema'],
                    'AttributeDefinitions': table_def['attribute_definitions'],
                    'ProvisionedThroughput': table_def['provisioned_throughput']
                }
                
                # GSI가 있는 경우 추가
                if 'global_secondary_indexes' in table_def:
                    params['GlobalSecondaryIndexes'] = table_def['global_secondary_indexes']
                
                # 테이블 생성
                dynamodb_client.create_table(**params)
                
                # 테이블 생성 완료 대기
                print(f"테이블 생성 대기 중: {table_name}")
                waiter = dynamodb_client.get_waiter('table_exists')
                waiter.wait(TableName=table_name)
                
                # TTL 설정이 있는 경우 적용
                if 'ttl' in table_def:
                    dynamodb_client.update_time_to_live(
                        TableName=table_name,
                        TimeToLiveSpecification=table_def['ttl']
                    )
                
                print(f"테이블 생성 완료: {table_name}")
            else:
                print(f"테이블 이미 존재함: {table_name}")
        
        return True
    except ClientError as e:
        print(f"DynamoDB 테이블 생성 중 오류 발생: {e.response['Error']['Message']}")
        return False