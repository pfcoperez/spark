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

object DBConfig {
  def prepareEnvironment(vaultHost: String,
                         vaultToken: String,
                         options: Map[String, String]): Map[String, String] = {
    options.filter(_._1.endsWith("DB_USER_VAULT_PATH")).flatMap{case (_, path) =>
      val (pass, user) = VaultHelper.getPassPrincipalFromVault(vaultHost, path, vaultToken)
      Seq(("spark.db.enable", "true"), ("spark.db.user", user), ("spark.db.pass", pass))
    }
  }
}
