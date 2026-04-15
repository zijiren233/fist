{{- define "fist.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "fist.labels" -}}
helm.sh/chart: {{ include "fist.chart" . }}
{{ include "fist.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "fist.selectorLabels" -}}
app.kubernetes.io/name: fist
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "fist.validateNamespace" -}}
{{- if ne .Release.Namespace "sealyun" -}}
{{- fail "fist chart currently requires installation into namespace sealyun because auth code hardcodes fist.sealyun.svc.cluster.local" -}}
{{- end -}}
{{- end -}}

{{- define "fist.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}

{{- define "fist.auth.name" -}}
fist
{{- end -}}

{{- define "fist.auth.serviceName" -}}
fist
{{- end -}}

{{- define "fist.auth.tlsSecretName" -}}
{{- default "fist" .Values.auth.tlsSecret.name -}}
{{- end -}}

{{- define "fist.auth.configMapName" -}}
{{- default "fist-authz-webhook" .Values.authz.configMapName -}}
{{- end -}}

{{- define "fist.terminal.name" -}}
fist-terminal
{{- end -}}

{{- define "fist.rbacApp.name" -}}
fist-rbac
{{- end -}}

{{- define "fist.adminServiceAccountName" -}}
{{- default "admin" .Values.adminServiceAccount.name -}}
{{- end -}}

{{- define "fist.rbacApp.adminSecretName" -}}
{{- default "fist-admin" .Values.rbacApp.adminSecret.name -}}
{{- end -}}
