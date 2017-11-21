/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.spark.security

import org.apache.spark.internal.Logging

object VaultHelper extends Logging {

  var token: Option[String] = None
  lazy val jsonTempTokenTemplate: String = "{ \"token\" : \"_replace_\" }"
  lazy val jsonRoleSecretTemplate: String = "{ \"role_id\" : \"_replace_role_\"," +
    " \"secret_id\" : \"_replace_secret_\"}"

  def getTokenFromAppRole(vaultUrl: String,
                          roleId: String,
                          secretId: String): String = {
    val requestUrl = s"$vaultUrl/v1/auth/approle/login"
    logDebug(s"Requesting login from app and role: $requestUrl")
    val replace: String = jsonRoleSecretTemplate.replace("_replace_role_", roleId)
      .replace("_replace_secret_", secretId)
    logDebug(s"getting secret: $secretId and role: $roleId")
    logDebug(s"generated JSON: $replace")
    val jsonAppRole = replace
    HTTPHelper.executePost(requestUrl, "auth",
      None, Some(jsonAppRole))("client_token").asInstanceOf[String]
  }

  def getRoleIdFromVault(vaultUrl: String,
                         role: String): String = {
    val requestUrl = s"$vaultUrl/v1/auth/approle/role/$role/role-id"
    if (!token.isDefined) token = {
      logDebug(s"Requesting token from app role: $role")
      Option(VaultHelper.getTokenFromAppRole(vaultUrl,
        sys.env("VAULT_ROLE_ID"),
        sys.env("VAULT_SECRET_ID")))
    }
    logDebug(s"Requesting Role ID from Vault: $requestUrl")
    HTTPHelper.executeGet(requestUrl, "data",
      Some(Seq(("X-Vault-Token", token.get))))("role_id").asInstanceOf[String]
  }

  def getSecretIdFromVault(vaultUrl: String,
                           role: String): String = {
    val requestUrl = s"$vaultUrl/v1/auth/approle/role/$role/secret-id"
    if (!token.isDefined) token = {
      logDebug(s"Requesting token from app role: $role")
      Option(VaultHelper.getTokenFromAppRole(vaultUrl,
        sys.env("VAULT_ROLE_ID"),
        sys.env("VAULT_SECRET_ID")))
    }

    logDebug(s"Requesting Secret ID from Vault: $requestUrl")
    HTTPHelper.executePost(requestUrl, "data",
      Some(Seq(("X-Vault-Token", token.get))))("secret_id").asInstanceOf[String]
  }

  def getTemporalToken(vaultUrl: String, token: String): String = {
    val requestUrl = s"$vaultUrl/v1/sys/wrapping/wrap"
    logDebug(s"Requesting temporal token: $requestUrl")

    val jsonToken = jsonTempTokenTemplate.replace("_replace_", token)

    HTTPHelper.executePost(requestUrl, "wrap_info",
      Some(Seq(("X-Vault-Token", token), ("X-Vault-Wrap-TTL", sys.env.get("VAULT_WRAP_TTL")
        .getOrElse("2000")))), Some(jsonToken))("token").asInstanceOf[String]
  }

  def getKeytabPrincipalFromVault(vaultUrl: String,
                                  token: String,
                                  vaultPath: String): (String, String) = {
    val requestUrl = s"$vaultUrl/$vaultPath"
    logDebug(s"Requesting Keytab and principal: $requestUrl")
    val data = HTTPHelper.executeGet(requestUrl, "data", Some(Seq(("X-Vault-Token", token))))
    val keytab64 = data.find(_._1.contains("keytab")).get._2.asInstanceOf[String]
    val principal = data.find(_._1.contains("principal")).get._2.asInstanceOf[String]
    (keytab64, principal)
  }

  // TODO refactor these two functions into one
  def getMesosPrincipalAndSecret(vaultUrl: String,
                                 token: String,
                                 instanceName: String): (String, String) = {
    getPassPrincipalFromVault(vaultUrl, s"/v1/userland/passwords/$instanceName/mesos", token)
  }

  def getPassPrincipalFromVault(vaultUrl: String,
                                vaultPath: String,
                                token: String): (String, String) = {
    val requestUrl = s"$vaultUrl/$vaultPath"
    logDebug(s"Requesting user and pass: $requestUrl")
    val data = HTTPHelper.executeGet(requestUrl, "data", Some(Seq(("X-Vault-Token", token))))
    val pass = data.find(_._1.contains("pass")).get._2.asInstanceOf[String]
    val principal = data.find(_._1.contains("user")).get._2.asInstanceOf[String]
    (pass, principal)
  }

  def getTrustStore(vaultUrl: String, token: String, certVaultPath: String): String = {
    val requestUrl = s"$vaultUrl/$certVaultPath"
    val truststoreVaultPath = s"$requestUrl"

    logDebug(s"Requesting truststore: $truststoreVaultPath")
    val data = HTTPHelper.executeGet(requestUrl,
      "data", Some(Seq(("X-Vault-Token", token))))
    val trustStore = data.find(_._1.endsWith("_crt")).get._2.asInstanceOf[String]
    trustStore
  }

  def getCertPassForAppFromVault(vaultUrl: String,
                                 appPassVaulPath: String,
                                 token: String): String = {
    logDebug(s"Requesting Cert Pass For App: $appPassVaulPath")
    val requestUrl = s"$vaultUrl/$appPassVaulPath"
    HTTPHelper.executeGet(requestUrl,
      "data", Some(Seq(("X-Vault-Token", token))))("pass").asInstanceOf[String]
  }

  def getCertKeyForAppFromVault(vaultUrl: String,
                                vaultPath: String,
                                token: String): (String, String) = {
    logDebug(s"Requesting Cert Key For App: $vaultPath")
    val requestUrl = s"$vaultUrl/$vaultPath"
    val data = HTTPHelper.executeGet(requestUrl,
      "data", Some(Seq(("X-Vault-Token", token))))
    val certs = data.find(_._1.endsWith("_crt")).get._2.asInstanceOf[String]
    val key = data.find(_._1.endsWith("_key")).get._2.asInstanceOf[String]
    (key, certs)
  }

  def getRealToken(vaultUrl: String, token: String): String = {
    val requestUrl = s"$vaultUrl/v1/sys/wrapping/unwrap"
    logDebug(s"Requesting real Token: $requestUrl")
    HTTPHelper.executePost(requestUrl,
      "data", Some(Seq(("X-Vault-Token", token))))("token").asInstanceOf[String]
  }
}
