#!/bin/bash
# Lambda 배포 스크립트

set -e

# 기본 설정 변수
ENV=${1:-dev}
REGION=${2:-us-east-1}
S3_BUCKET="lambda-deployment-packages"

# 색상 코드
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}WGA Lambda 함수 배포 스크립트 - 환경: ${ENV}, 리전: ${REGION}${NC}"

# S3 버킷 존재 확인 및 생성
if ! aws s3 ls "s3://${S3_BUCKET}" --region ${REGION} 2>&1 > /dev/null; then
    echo -e "${YELLOW}S3 버킷 ${S3_BUCKET}이 존재하지 않습니다. 생성합니다...${NC}"
    aws s3 mb "s3://${S3_BUCKET}" --region ${REGION}
else
    echo -e "${GREEN}S3 버킷 ${S3_BUCKET}이 이미 존재합니다.${NC}"
fi

# 임시 디렉토리 생성
TEMP_DIR=$(mktemp -d)
echo -e "${GREEN}임시 디렉토리 생성: ${TEMP_DIR}${NC}"

# 공통 모듈 준비
mkdir -p ${TEMP_DIR}/common
echo -e "${GREEN}공통 모듈 복사...${NC}"
cp -r lambda_functions/common/* ${TEMP_DIR}/common/

# 함수별 배포 패키지 생성 및 업로드
for func in auth cloudtrail policy_recommendation; do
    echo -e "${YELLOW}함수 ${func} 배포 패키지 생성 중...${NC}"
    
    # 함수별 디렉토리 생성
    FUNC_DIR=${TEMP_DIR}/${func}
    mkdir -p ${FUNC_DIR}
    
    # 함수 코드 복사
    cp -r lambda_functions/${func}/* ${FUNC_DIR}/
    
    # 공통 모듈 복사
    cp -r ${TEMP_DIR}/common ${FUNC_DIR}/
    
    # 현재 디렉토리로 이동
    cd ${FUNC_DIR}
    
    # pip로 의존성 설치
    if [ -f "requirements.txt" ]; then
        echo -e "${GREEN}의존성 패키지 설치 중...${NC}"
        pip install -r requirements.txt -t .
    fi
    
    # 배포 패키지 생성 (ZIP)
    echo -e "${GREEN}ZIP 파일 생성 중...${NC}"
    zip -q -r ${TEMP_DIR}/wga-${func}.zip .
    
    # 원래 디렉토리로 돌아가기
    cd -
    
    # S3에 업로드
    echo -e "${GREEN}S3에 업로드 중...${NC}"
    aws s3 cp ${TEMP_DIR}/wga-${func}.zip s3://${S3_BUCKET}/ --region ${REGION}
    
    echo -e "${GREEN}함수 ${func} 배포 패키지 업로드 완료!${NC}"
done

# CloudFormation 템플릿 업로드
echo -e "${YELLOW}CloudFormation 템플릿 업로드 중...${NC}"
aws s3 cp cloudformation-template.yaml s3://${S3_BUCKET}/ --region ${REGION}

# CloudFormation 스택 배포
echo -e "${YELLOW}CloudFormation 스택 배포 중...${NC}"

# 환경에 맞는 파라미터 파일 로드
if [ -f "parameters-${ENV}.json" ]; then
    PARAMS_FILE="parameters-${ENV}.json"
    echo -e "${GREEN}파라미터 파일 사용: ${PARAMS_FILE}${NC}"
    
    aws cloudformation deploy \
        --template-url https://${S3_BUCKET}.s3.amazonaws.com/cloudformation-template.yaml \
        --stack-name wga-lambda-${ENV} \
        --parameter-overrides file://${PARAMS_FILE} \
        --capabilities CAPABILITY_NAMED_IAM \
        --region ${REGION}
else
    echo -e "${RED}경고: 파라미터 파일 parameters-${ENV}.json이 없습니다. 기본값으로 배포합니다.${NC}"
    
    # 기본 파라미터 값 (실제 프로젝트에서는 사용자 입력을 받는 것이 좋음)
    aws cloudformation deploy \
        --template-url https://${S3_BUCKET}.s3.amazonaws.com/cloudformation-template.yaml \
        --stack-name wga-lambda-${ENV} \
        --parameter-overrides \
            EnvironmentName=${ENV} \
            CognitoDomain="https://wga-auth.auth.${REGION}.amazoncognito.com" \
            UserPoolId="us-east-1_XXXXXXXX" \
            CognitoClientId="XXXXXXXXXXXXXXXXXXXXX" \
            CognitoIdentityPoolId="us-east-1:XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" \
            OutputBucketName="wga-outputbucket" \
        --capabilities CAPABILITY_NAMED_IAM \
        --region ${REGION}
fi

# 임시 디렉토리 제거
echo -e "${GREEN}임시 디렉토리 정리 중...${NC}"
rm -rf ${TEMP_DIR}

# 배포 완료 후 API 엔드포인트 정보 출력
echo -e "${YELLOW}스택 정보 조회 중...${NC}"
API_ENDPOINT=$(aws cloudformation describe-stacks --stack-name wga-lambda-${ENV} --region ${REGION} --query "Stacks[0].Outputs[?OutputKey=='ApiEndpoint'].OutputValue" --output text)

echo -e "${GREEN}배포 완료!${NC}"
echo -e "${GREEN}API 엔드포인트: ${API_ENDPOINT}${NC}"