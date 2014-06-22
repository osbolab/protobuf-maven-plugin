/*
 * Copyright 2012, by Yet another Protobuf Maven Plugin Developers
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.github.igorpetruk.protobuf.maven.plugin;

import java.io.File;
import java.io.FilenameFilter;

/**
 * @author igor.petrouk@gmail.com (Igor Petrouk)
 */
public class ProtoFileFilter implements FilenameFilter {
  String extension;

  public ProtoFileFilter(String extension) {
    this.extension = extension;
  }

  @Override
  public boolean accept(File dir, String name) {
    return name.endsWith(extension);
  }
}
