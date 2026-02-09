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
  volumes:
  - name: jenkins-agent
    emptyDir: {}
  - name: m2-repo
    emptyDir: {}
  containers:
  - name: jnlp
    image: jenkins/inbound-agent:latest
    args: ['$(JENKINS_SECRET)', '$(JENKINS_NAME)']
    workingDir: /tmp/agent
    env:
    - name: JENKINS_AGENT_WORKDIR
      value: /tmp/agent
    volumeMounts:
    - name: jenkins-agent
      mountPath: /tmp/agent
  - name: maven
    image: maven:3.9.9-eclipse-temurin-17
    command: ['cat']
    tty: true
    env:
    - name: MAVEN_CONFIG
      value: /tmp/.m2
    volumeMounts:
    - name: m2-repo
      mountPath: /tmp/.m2
  - name: oc
    image: image-registry.openshift-image-registry.svc:5000/openshift/cli:latest
    command: ['cat']
    tty: true
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
                        ARCH=$(uname -m)
                        if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
                          HELM_PKG="helm-v3.14.4-linux-arm64.tar.gz"
                        else
                          HELM_PKG="helm-v3.14.4-linux-amd64.tar.gz"
                        fi
                        curl -sSL "https://get.helm.sh/${HELM_PKG}" -o /tmp/helm.tgz
                        tar -xzf /tmp/helm.tgz -C /tmp
                        if [ -d /tmp/linux-arm64 ]; then
                          chmod +x /tmp/linux-arm64/helm
                          export PATH="/tmp/linux-arm64:$PATH"
                        else
                          chmod +x /tmp/linux-amd64/helm
                          export PATH="/tmp/linux-amd64:$PATH"
                        fi
                      fi

                      helm lint "${CHART_PATH}"
                      helm upgrade --install "${HELM_RELEASE}" "${CHART_PATH}" \
                        --namespace "${OPENSHIFT_PROJECT}" \
                        --set image.repository="${IMAGE_REPOSITORY}" \
                        --set image.tag="${IMAGE_TAG}" \
                        --set secret.name="${APP_NAME}-secret"
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
