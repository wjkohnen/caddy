<!DOCTYPE html>
<html>
<head>
<title>CSPTemplate</title>
<style{{if .CSPNonce}} nonce="{{.CSPNonce}}"{{end}}>* { padding: 0; margin: 0; }</style>
</head>
<body>
{{.Include "header.html"}}
<h1>{{.Path}}</h1>
{{range .Items}}
<a href="{{.URL}}">{{.Name}}</a><br>
{{end}}
</body>
</html>
