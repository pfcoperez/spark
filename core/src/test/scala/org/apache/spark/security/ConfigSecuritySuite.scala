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

import org.apache.spark.SparkFunSuite

import org.scalatest._


class ConfigSecuritySuite extends SparkFunSuite with Matchers {
  test("extractSecretFromEnv with a malformed property") {

    val envProp = Map("SPARK_SECURITY_KAFKA_ENABLE" -> "true",
      "SPARK_SECURITY_" -> "true")
    an [IllegalArgumentException] should be thrownBy ConfigSecurity.extractSecretFromEnv(envProp)
  }

  test("extractSecretFromEnv with 2 wrong security properties" +
    " should return only the ones with the enable keyword") {

    val envProp = Map("SPARK_SECURITY_KAFKA_ENABLE" -> "true",
      "SPARK_SECURITY_HDFS_ENABLE" -> "true",
      "SPARK_SECURITY_DATASTORE_ENABLE" -> "true",
      "SPARK_SECURITY_KERBEROS_ENABLE" -> "true",
      "SPARK_SECURITY_WRONG1_P1" -> "true",
      "SPARK_SECURITY_WRONG2_P2" -> "true")

    assert(ConfigSecurity.extractSecretFromEnv(envProp) ===
      Map("kerberos" -> Map("KERBEROS_ENABLE" -> "true"),
        "hdfs" -> Map("HDFS_ENABLE" -> "true"),
        "datastore" -> Map("DATASTORE_ENABLE" -> "true"),
        "kafka" -> Map("KAFKA_ENABLE" -> "true")))
  }

  /**
    * getVaultUri
    */

  val vaultProtocol = Option("https")
  val vaultHost = Option("vault.labs.stratio.com")
  val vaultPort = Option("8200")
  val expectedResult = "https://vault.labs.stratio.com:8200"


  test("getVaultUri with all the parameters given") {
    val vaultUri = ConfigSecurity.getVaultUri(vaultProtocol, vaultHost, vaultPort)
    assert(vaultUri === Option(expectedResult))
  }

  test("getVaultUri without one of the parameters needed") {
    val vaultUri = ConfigSecurity.getVaultUri(None, vaultHost, vaultPort)
    assert(vaultUri === None)
  }

  test("getVaultUri without none of the parameters needed") {
    val vaultUri = ConfigSecurity.getVaultUri(None, None, None)
    assert(vaultUri === None)
  }
}


