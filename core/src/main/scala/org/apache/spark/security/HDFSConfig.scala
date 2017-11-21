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

import java.io.File
import java.nio.file.{Files, Paths}
import java.nio.file.attribute.PosixFilePermissions

import org.apache.spark.internal.Logging

object HDFSConfig extends Logging{

  private def downloadFile(url: String,
                           fileToDownload: String,
                           outputhPath: String,
                           connectTimeout: Int,
                           readTimeout: Int) {
    logInfo(s"extracting $url/$fileToDownload")
    new File(outputhPath).mkdirs
    val src = get(s"$url/$fileToDownload", connectTimeout, readTimeout).mkString("")
    val downloadFile = Files.createFile(Paths.get(s"$outputhPath/$fileToDownload"),
      PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
    downloadFile.toFile.deleteOnExit() // just to be sure
    Files.write(downloadFile, src.getBytes)
  }

  private def get(url: String,
                  connectTimeout: Int,
                  readTimeout: Int): String = {
    import java.net.{URL, HttpURLConnection}
    val requestMethod = "GET"
    val connection = (new URL(url)).openConnection.asInstanceOf[HttpURLConnection]
    connection.setConnectTimeout(connectTimeout)
    connection.setReadTimeout(readTimeout)
    connection.setRequestMethod(requestMethod)
    val inputStream = connection.getInputStream
    val content = scala.io.Source.fromInputStream(inputStream).mkString("")
    if (inputStream != null) inputStream.close
    content
  }


  def prepareEnviroment(options: Map[String, String]): Map[String, String] = {
    require(options.get("HDFS_CONF_URI").isDefined,
      "a proper HDFS URI must be configured to get Hadoop Configuration")
    require(sys.env.get("HADOOP_CONF_DIR").isDefined,
      "a proper Hadoop Conf Dir must be configured to store Hadoop Configuration")
    val connectTimeout: Int = options.get("HDFS_CONF_CONNECT_TIMEOUT").getOrElse("5000").toInt
    val readTimeout: Int = options.get("HDFS_CONF_READ_TIMEOUT").getOrElse("5000").toInt
    val hadoopConfUri = options.get("HDFS_CONF_URI").get
    val hadoopConfDir = sys.env.get("HADOOP_CONF_DIR").get
    downloadFile(hadoopConfUri, "core-site.xml", hadoopConfDir, connectTimeout, readTimeout)
    downloadFile(hadoopConfUri, "hdfs-site.xml", hadoopConfDir, connectTimeout, readTimeout)
    downloadFile(hadoopConfUri, "krb5.conf", "/etc/", connectTimeout, readTimeout)
    Map.empty[String, String]
  }
}