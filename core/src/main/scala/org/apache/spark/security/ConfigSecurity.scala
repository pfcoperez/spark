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

import scala.util.{Failure, Success, Try}

import org.apache.spark.internal.Logging

object ConfigSecurity extends Logging{

  var vaultToken: Option[String] = None
  val vaultHost: Option[String] = sys.env.get("VAULT_HOST")
  val vaultUri: Option[String] =
    getVaultUri(sys.env.get("VAULT_PROTOCOL"), vaultHost, sys.env.get("VAULT_PORT"))

  def getVaultUri(vaultProtocol: Option[String],
                  vaultHost: Option[String],
                  vaultPort: Option[String]): Option[String] = {
    (vaultProtocol, vaultHost, vaultPort) match {
      case (Some(vaultProtocol), Some(vaultHost), Some(vaultPort)) =>
        val vaultUri = s"$vaultProtocol://$vaultHost:$vaultPort"
        logDebug(s"Vault uri: $vaultUri found, any Vault Connection will use it")
        Option(vaultUri)
      case _ =>
        logDebug("No Vault information found, any Vault Connection will fail")
        None
    }
  }

  def prepareEnvironment(vaultAppToken: Option[String] = None,
                         vaulHost: Option[String] = None): Map[String, String] = {

    logDebug(s"env VAR: ${sys.env.mkString("\n")}")
    val secretOptionsMap = ConfigSecurity.extractSecretFromEnv(sys.env)
    logDebug(s"secretOptionsMap: ${secretOptionsMap.mkString("\n")}")
    loadingConf(secretOptionsMap)
    vaultToken = if (vaultAppToken.isDefined) {
      vaultAppToken
    } else sys.env.get("VAULT_TOKEN")
    if(vaultToken.isDefined) {
      require(vaultUri.isDefined, "A proper vault host is required")
      logDebug(s"env VAR: ${sys.env.mkString("\n")}")
      prepareEnvironment(vaultUri.get, vaultToken.get, secretOptionsMap)
    }
    else Map()
  }


   def extractSecretFromEnv(env: Map[String, String]): Map[String,
    Map[String, String]] = {
    val sparkSecurityPrefix = "spark_security_"

    val extract: ((String, String)) => String = (keyValue: (String, String)) => {
      val (key, _) = keyValue

      val securityProp = key.toLowerCase

      if (securityProp.startsWith(sparkSecurityPrefix)) {
        val result = Try(securityProp.split("_")(2))
         result match {
          case Success(value) => value
          case Failure(e) =>
            throw new IllegalArgumentException(
              s"Your SPARK_SECURITY property: $securityProp is malformed")
        }
      } else {
        ""
      }
    }

    env.groupBy(extract).filter(_._2.exists(_._1.toLowerCase.contains("enable")))
      .flatMap{case (key, value) =>
      if (key.nonEmpty) Option((key, value.map{case (propKey, propValue) =>
        (propKey.split(sparkSecurityPrefix.toUpperCase).tail.head, propValue)
      }))
      else None
    }
  }

  private def loadingConf(secretOptions: Map[String, Map[String, String]]): Unit = {
    secretOptions.foreach { case (key, options) =>
      key match {
        case "hdfs" =>
          HDFSConfig.prepareEnviroment(options)
          logDebug("Downloaded HDFS conf")
        case _ =>
      }
    }
  }

  private def prepareEnvironment(vaultHost: String,
                                 vaultToken: String,
                                 secretOptions: Map[String,
                                   Map[String, String]]): Map[String, String] =
    secretOptions flatMap {
      case ("kerberos", options) =>
        KerberosConfig.prepareEnviroment(vaultHost, vaultToken, options)
      case ("datastore", options) =>
        SSLConfig.prepareEnvironment(
            vaultHost, vaultToken, SSLConfig.sslTypeDataStore, options)
      case ("db", options) =>
        DBConfig.prepareEnvironment(vaultHost, vaultToken, options)
      case _ => Map.empty[String, String]
    }

}
