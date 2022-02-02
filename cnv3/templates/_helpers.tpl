{{- define "mpName" -}}
pan-mp-{{ .Release.Name }}
{{- end -}}
{{- define "dpName" -}}
pan-dp-{{ $.Release.Name }}
{{- end -}}

{{- define "netAttachments" -}}
{{- $i := 1 -}}
{{- $dpname := .dpname -}}
{{- $fwid := .fwid -}}
{{- range .nets -}}
    {{- if gt $i 1 -}},{{- end -}}
    {{ if eq .name "ha2" }}
        {{- $dpname -}}-ha-net-attach-{{- $fwid -}}@eth{{- $i -}}
    {{ else }}
        {{- $dpname -}}-{{- .name -}}@eth{{- $i -}}
    {{- end -}}
    {{- $i = add1 $i -}}
{{- end -}}
{{- end -}}
