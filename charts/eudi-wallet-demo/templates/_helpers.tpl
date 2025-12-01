{{- define "eudi-wallet-demo.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "eudi-wallet-demo.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "eudi-wallet-demo.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "eudi-wallet-demo.labels" -}}
helm.sh/chart: {{ include "eudi-wallet-demo.chart" . }}
{{ include "eudi-wallet-demo.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "eudi-wallet-demo.selectorLabels" -}}
app.kubernetes.io/name: {{ include "eudi-wallet-demo.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "eudi-wallet-demo.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{ default (printf "%s-sa" (include "eudi-wallet-demo.fullname" .)) .Values.serviceAccount.name }}
{{- else -}}
{{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{- define "eudi-wallet-demo.dbSecretName" -}}
{{- $vendor := default "dev-file" .Values.keycloak.database.vendor | lower -}}
{{- if or (eq $vendor "dev-file") (eq $vendor "dev-mem") -}}
{{- "" -}}
{{- else if .Values.keycloak.database.existingSecret -}}
{{ .Values.keycloak.database.existingSecret }}
{{- else if .Values.postgresql.enabled -}}
{{ printf "%s-postgresql" (include "eudi-wallet-demo.fullname" .) }}
{{- else -}}
{{ printf "%s-keycloak-db" (include "eudi-wallet-demo.fullname" .) }}
{{- end -}}
{{- end -}}

{{- define "eudi-wallet-demo.usesDatabase" -}}
{{- $vendor := default "dev-file" .Values.keycloak.database.vendor | lower -}}
{{- not (or (eq $vendor "dev-file") (eq $vendor "dev-mem")) -}}
{{- end -}}

{{- define "eudi-wallet-demo.usePostgres" -}}
{{- $vendor := default "dev-file" .Values.keycloak.database.vendor | lower -}}
{{- or .Values.postgresql.enabled (eq $vendor "postgres") -}}
{{- end -}}

{{- define "eudi-wallet-demo.keycloakCommand" -}}
{{- $vendor := default "dev-file" .Values.keycloak.database.vendor | lower -}}
{{- if or (eq $vendor "dev-file") (eq $vendor "dev-mem") -}}
start-dev
{{- else -}}
start
{{- end -}}
{{- end -}}
