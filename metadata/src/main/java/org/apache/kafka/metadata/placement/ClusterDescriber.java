/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kafka.metadata.placement;

import org.apache.kafka.common.Uuid;
import org.apache.kafka.common.annotation.InterfaceStability;

import java.util.Iterator;


/**
 * Can describe a cluster to a ReplicaPlacer.
 */
@InterfaceStability.Unstable
public interface ClusterDescriber extends DefaultDirProvider {
    /**
     * Get an iterator through the usable brokers.
     */
    Iterator<UsableBroker> usableBrokers();

    /**
     * Get the default directory for new partitions placed in a given broker.
     */
    Uuid defaultDir(int brokerId);
}
