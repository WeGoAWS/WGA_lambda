# WGA Lambda 프로젝트

WGA(Wise Global Audit) 애플리케이션의 FastAPI 백엔드를 AWS Lambda로 마이그레이션한 프로젝트입니다. 이 프로젝트는 CloudTrail 로그 분석 및 IAM 정책 추천 기능을 서버리스 아키텍처로 구현합니다.

## 프로젝트 구조

```
wga-lambda/
├── cloudformation-template.yaml  # CloudFormation 템플릿
├── deploy.sh                     # 배포 스크립트
├── parameters-dev.json           # 개발 환경 파라미터 
├── dynamodb-migration.py         # MongoDB에서 DynamoDB로 데이터 마이그레이션 스크립트
└── lambda_functions/
    ├── common/                   # 공통 모듈
    │   ├── config.py             # 설정 정보
    │   ├── db.py                 # DynamoDB 연동 모듈
    │   └── utils.py              # 유틸리티 함수
    ├── auth/                     # 인증 관련 Lambda 함수
    │   ├── lambda_function.py    # Lambda 핸들러
    │   ├── auth_service.py       # 인증 서비스 모듈
    │   └── requirements.txt      # 필요한 패키지 목록
    ├── cloudtrail/               # CloudTrail 관련 Lambda 함수
    │   ├── lambda_function.py    # Lambda 핸들러
    │   ├── cloudtrail_service.py # CloudTrail 서비스 모듈
    │   └── requirements.txt      # 필요한 패키지 목록
    └── policy_recommendation/    # 정책 추천 Lambda 함수
        ├── lambda_function.py    # Lambda 핸들러
        ├── recommendation_service.py # 정책 추천 서비스 모듈
        └── requirements.txt      # 필요한 패키지 목록
```

## 사전 준비 사항

1. **AWS CLI 설치**
   ```bash
   # macOS (homebrew 사용 시)
   brew install awscli

   # 또는 pip로 설치
   pip install awscli

   # 또는 AWS 공식 설치 스크립트 사용
   curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   unzip awscliv2.zip
   sudo ./aws/install
   ```

2. **AWS 자격 증명 구성**
   ```bash
   aws configure
   ```
   필요한 정보:
   - AWS Access Key ID
   - AWS Secret Access Key
   - Default region name (예: us-east-1)
   - Default output format (json)

3. **필요한 AWS 서비스 권한**
   배포에 사용하는 IAM 사용자/역할에 다음 권한이 필요합니다:
   - CloudFormation 스택 생성 및 관리
   - IAM 역할 및 정책 생성
   - Lambda 함수 생성 및 업데이트
   - API Gateway 생성 및 설정
   - DynamoDB 테이블 생성
   - S3 버킷 생성 및 객체 업로드

## 배포 방법

1. **파라미터 파일 설정**
   `parameters-dev.json` 파일에 필요한 설정을 입력합니다:
   ```json
   [
     {
       "ParameterKey": "EnvironmentName",
       "ParameterValue": "dev"
     },
     {
       "ParameterKey": "CognitoDomain",
       "ParameterValue": "https://your-cognito-domain.auth.us-east-1.amazoncognito.com"
     },
     {
       "ParameterKey": "UserPoolId",
       "ParameterValue": "us-east-1_XXXXXXXX"
     },
     {
       "ParameterKey": "CognitoClientId",
       "ParameterValue": "your-client-id"
     },
     {
       "ParameterKey": "CognitoIdentityPoolId",
       "ParameterValue": "us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
     },
     {
       "ParameterKey": "OutputBucketName",
       "ParameterValue": "wga-outputbucket"
     }
   ]
   ```

2. **배포 스크립트 실행**
   ```bash
   # 배포 스크립트에 실행 권한 부여
   chmod +x deploy.sh

   # 개발 환경으로 배포 (기본 리전: us-east-1)
   ./deploy.sh dev

   # 또는 리전을 지정하여 배포
   ./deploy.sh dev us-east-1
   ```

3. **배포 확인**
   배포가 완료되면 API 엔드포인트 URL이 출력됩니다:
   ```
   배포 완료!
   API 엔드포인트: https://abcd1234.execute-api.us-east-1.amazonaws.com/dev
   ```

## 배포 과정 설명

`deploy.sh` 스크립트를 실행하면 다음과 같은 과정이 진행됩니다:

### 1. 배포 환경 준비
- 배포 환경(dev)과 리전(us-east-1) 설정
- Lambda 배포 패키지를 저장할 S3 버킷 확인 및 생성
- 임시 작업 디렉토리 생성

### 2. Lambda 함수 패키지 준비
- 각 Lambda 함수의 소스 코드와 공통 모듈을 임시 디렉토리로 복사
- 필요한 패키지 설치(requirements.txt)
- ZIP 배포 패키지 생성
- S3 버킷에 패키지 업로드

### 3. CloudFormation 배포
- CloudFormation 템플릿 S3 업로드
- 파라미터 파일을 사용하여 CloudFormation 스택 생성/업데이트
- 스택 생성 완료 대기

### 4. 생성되는 AWS 리소스
- **DynamoDB 테이블**
  - Sessions-dev: 사용자 세션 정보 저장
  - Users-dev: 사용자 정보 저장
  - AnalysisResults-dev: 정책 분석 결과 저장
- **Lambda 함수**
  - wga-auth-dev: 인증 관련 기능
  - wga-cloudtrail-dev: CloudTrail 로그 조회 및 분석
  - wga-policy-recommendation-dev: IAM 정책 추천 기능
- **IAM 역할**
  - wga-lambda-execution-role-dev: Lambda 함수 실행 권한
- **API Gateway**
  - wga-api-dev: REST API 및 엔드포인트

## 데이터 마이그레이션

MongoDB에서 DynamoDB로 데이터를 마이그레이션하려면 다음 스크립트를 실행합니다:

```bash
# 필요한 패키지 설치
pip install boto3 pymongo

# MongoDB URI 설정
export MONGODB_URI="mongodb://username:password@host:port/dbname"
export MONGODB_DB_NAME="wga"

# 마이그레이션 실행
python dynamodb-migration.py --env dev --region us-east-1
```

## API 엔드포인트

배포 후 사용 가능한 API 엔드포인트:

### 인증 API
- `GET /auth` - 현재 로그인 상태 확인
- `GET /auth/logout` - 로그아웃
- `POST /auth/verify-token` - 토큰 검증

### CloudTrail API
- `GET /cloudtrail/logs` - CloudTrail 로그 조회
- `GET /cloudtrail/analyze-logs` - CloudTrail 로그 분석

### 정책 추천 API
- `GET /policy-recommendation/process-multiple-analyses` - 분석 결과 처리
- `POST /policy-recommendation/apply-policy-changes` - 정책 변경 적용

## 로컬 개발 및 테스트

Lambda 함수를 로컬에서 테스트하려면 AWS SAM CLI를 사용할 수 있습니다:

```bash
# AWS SAM CLI 설치
pip install aws-sam-cli

# 로컬에서 Lambda 함수 실행
sam local invoke "WgaAuthFunction" -e events/auth-event.json
```

## 문제 해결

### 배포 중 문제
- **AWS CLI 명령 오류**: AWS CLI가 설치되어 있는지 확인합니다.
- **권한 부족 오류**: AWS 자격 증명에 필요한 권한이 있는지 확인합니다.
- **CloudFormation 스택 롤백**: AWS CloudFormation 콘솔에서 이벤트 탭을 확인하여 실패 원인을 파악합니다.

### Lambda 함수 오류
- **Lambda 실행 오류**: CloudWatch Logs에서 Lambda 함수 로그를 확인합니다.
- **타임아웃 오류**: Lambda 함수의 제한 시간을 늘리거나 코드를 최적화합니다.
- **메모리 부족**: Lambda 함수의 메모리 할당량을 늘립니다.

## 참고 자료

- [AWS Lambda 개발자 가이드](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html)
- [AWS CloudFormation 사용 설명서](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html)
- [Amazon DynamoDB 개발자 가이드](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html)
- [Amazon API Gateway 개발자 가이드](https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html)

## 라이선스

이 프로젝트는 MIT 라이선스로 배포됩니다.
