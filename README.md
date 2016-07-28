# Overview

- [Spring Boot](http://projects.spring.io/spring-boot/)
- [Spring Security](http://projects.spring.io/spring-security/)
- [Spring Security SAML](http://projects.spring.io/spring-security-saml/)
- [Thymeleaf](http://www.thymeleaf.org/)

## idp.xml

使用するIdentity Providerからsrc/main/resource/saml/idp.xmlにダウンロードしてください。

### OpenAMの場合

```
$ curl -o idp.xml https://[IDP Host Name]/[ContextPath]/saml2/jsp/exportmetadata.jsp
```

## samlKeystore.jks

src/main/resource/saml/samlKeystore.jksを作成してください。

```
$ keytool -genkeypair -alias apollo -keypass nalle123 -keystore samlKeystore.jks
```

