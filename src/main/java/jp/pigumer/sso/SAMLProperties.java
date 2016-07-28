/*
 * Copyright 2016 Pigumer Group Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jp.pigumer.sso;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix="saml")
public class SAMLProperties {

    private String storeFile = "classpath:/saml/samlKeystore.jks";

    private String storePass = "nalle123";

    private String defaultKey = "apollo";

    private String password = "nalle123";

    private String idpMetaFile = "/saml/idp.xml";

    private String entityId = "jp:pigumer:sp";

    public String getStoreFile() {
        return storeFile;
    }

    public void setStoreFile(String storeFile) {
        this.storeFile = storeFile;
    }

    public String getStorePass() {
        return storePass;
    }

    public void setStorePass(String storePass) {
        this.storePass = storePass;
    }

    public String getDefaultKey() {
        return defaultKey;
    }

    public void setDefaultKey(String defaultKey) {
        this.defaultKey = defaultKey;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getIdpMetaFile() {
        return idpMetaFile;
    }

    public void setIdpMetaFile(String idpMetaFile) {
        this.idpMetaFile = idpMetaFile;
    }

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(String entityId) {
        this.entityId = entityId;
    }
}
