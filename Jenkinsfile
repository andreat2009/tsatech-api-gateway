pipeline {
    agent {
        kubernetes {
            yaml """
apiVersion: v1
kind: Pod
metadata:
  labels:
    app: jenkins-agent-maven
spec:
  containers:
  - name: maven
    image: maven:3.9.9-eclipse-temurin-17
    command: ['cat']
    tty: true
    volumeMounts:
    - name: m2-repo
      mountPath: /root/.m2
  - name: oc
    image: quay.io/openshift/origin-cli:latest
    command: ['cat']
    tty: true
  volumes:
  - name: m2-repo
    emptyDir: {}
"""
        }
    }
    environment {
        APP_NAME = "api-gateway"
        HELM_RELEASE = "${HELM_RELEASE:-api-gateway}"
        CHART_PATH = "${CHART_PATH:-helm}"
    }
    stages {
        stage('Checkout') {
            steps { checkout scm }
        }
        stage('OpenShift Login') {
            steps {
                container('oc') {
                    withCredentials([string(credentialsId: 'openshift-token', variable: 'OPENSHIFT_TOKEN')]) {
                        sh '''
                          set -euo pipefail
                          OPENSHIFT_SERVER="${OPENSHIFT_SERVER:-https://api.crc.testing:6443}"
                          OPENSHIFT_PROJECT="${OPENSHIFT_NAMESPACE:-${OPENSHIFT_PROJECT:-ecommerce}}"
                          oc login --token="$OPENSHIFT_TOKEN" --server="$OPENSHIFT_SERVER" --insecure-skip-tls-verify=true
                          oc project "$OPENSHIFT_PROJECT"
                        '''
                    }
                }
            }
        }
        stage('Build Maven') {
            steps {
                container('maven') { sh 'mvn clean package -DskipTests' }
            }
        }
        stage('Build Image') {
            steps {
                container('oc') {
                    sh '''
                      set -euo pipefail
                      OPENSHIFT_PROJECT="${OPENSHIFT_NAMESPACE:-${OPENSHIFT_PROJECT:-ecommerce}}"
                      oc new-build --name="${APP_NAME}" --binary --strategy=docker >/dev/null 2>&1 || true
                      oc start-build "${APP_NAME}" --from-dir=. --follow
                    '''
                }
            }
        }
        stage('Helm Deploy') {
            steps {
                container('oc') {
                    sh '''
                      set -euo pipefail
                      OPENSHIFT_PROJECT="${OPENSHIFT_NAMESPACE:-${OPENSHIFT_PROJECT:-ecommerce}}"
                      IMAGE_REPOSITORY="${IMAGE_REPOSITORY:-image-registry.openshift-image-registry.svc:5000/${OPENSHIFT_PROJECT}/${APP_NAME}}"
                      IMAGE_TAG="${IMAGE_TAG:-latest}"

                      if ! command -v helm >/dev/null 2>&1; then
                        curl -sSL https://get.helm.sh/helm-v3.14.4-linux-amd64.tar.gz -o /tmp/helm.tgz
                        tar -xzf /tmp/helm.tgz -C /tmp
                        chmod +x /tmp/linux-amd64/helm
                        export PATH="/tmp/linux-amd64:$PATH"
                      fi

                      helm lint "${CHART_PATH}"
                      helm upgrade --install "${HELM_RELEASE}" "${CHART_PATH}" \
                        --namespace "${OPENSHIFT_PROJECT}" \
                        --set image.repository="${IMAGE_REPOSITORY}" \
                        --set image.tag="${IMAGE_TAG}" \
                        --set secret.name="${APP_NAME}Secret"
                    '''
                }
            }
        }
        stage('Rollout & Smoke') {
            steps {
                container('oc') {
                    sh '''
                      set -euo pipefail
                      OPENSHIFT_PROJECT="${OPENSHIFT_NAMESPACE:-${OPENSHIFT_PROJECT:-ecommerce}}"
                      oc rollout status deployment/${APP_NAME} --timeout=240s
                      ROUTE_HOST=$(oc -n "$OPENSHIFT_PROJECT" get route "${APP_NAME}" -o jsonpath='{.spec.host}' || true)
                      if [ -n "$ROUTE_HOST" ]; then
                        if command -v curl >/dev/null 2>&1; then
                          curl -k -fsS "https://${ROUTE_HOST}/actuator/health" >/dev/null
                        fi
                      fi
                    '''
                }
            }
        }
    }
}
