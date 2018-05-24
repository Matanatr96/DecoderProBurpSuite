# Decoder Pro

This is a simple burp suite plugin that cleans and decodes the raw request and response.

## Getting Started

1. Download  Burpsuite and simply the burp.jar file in this repo (burp/out/artifacts/burp_jar/burp.jar)
2. Upload it using the extender page

### Editing the regex

All youre gonna need to edit is the BurpExtender.java file. All the code needed for this plugin is in that file.
Regex's are in 

```
decodeText() {}
applyPattern() {}
removeHTMLTags() {}
```

Feel free to replace the regex with your own!

## Authors

Mostly reworked code from 
[PortSwigger](https://github.com/PortSwigger/json-beautifier)



