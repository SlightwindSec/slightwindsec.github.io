---
title: '{{ replace .File.ContentBaseName "-" " " | title }}'
date: {{ .Date }}
description: "Guide to emoji usage in Hugo"
tags: ["emoji"]
ShowToc: false
ShowBreadCrumbs: false
{{ if or .Params.math .Site.Params.math }}
{{ partial "math.html" . }}
{{ end }}
---