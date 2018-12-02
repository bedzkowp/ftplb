/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pl.edu.pw.elka.stud;

import org.onlab.packet.*;
import org.onlab.rest.AbstractWebApplication;
import org.onlab.rest.JsonBodyWriter;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.IPProtocolCriterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.HostAdminService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.packet.*;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.rest.AbstractWebResource;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent extends AbstractWebApplication {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected GroupService groupService;

    private ApplicationId appId;
    private FtpPacketProcessor ftpPacketProcessor = new FtpPacketProcessor();
    private TrafficSelector selector;
    private PacketPriority packetPriority = PacketPriority.HIGH;
    private Ip4Address sharedAddress;
    private List<Ip4Address> hostsAssignedToSharedAddress = new ArrayList<>();
    private Map<Ip4Address, List<Ip4Address>> hostsWithActiveFtpSessionsAssignedToOldSharedAddresses;
    private Random random = new Random();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("pl.edu.pw.elka.stud.psik");
        packetService.addProcessor(ftpPacketProcessor, PacketProcessor.director(2)); // TODO check priority
        requestIntercepts();

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(ftpPacketProcessor);
        ftpPacketProcessor = null;
        withdrawIntercepts();

        log.info("Stopped");
    }

    public void setSharedAddress(String address) {
        sharedAddress = Ip4Address.valueOf(address);
    }

    public void addHostToSharedAddress(String address) {
        hostsAssignedToSharedAddress.add(Ip4Address.valueOf(address));
    }

    public Ip4Address getNextHost() {
        int index = random.nextInt(hostsAssignedToSharedAddress.size());

        return hostsAssignedToSharedAddress.get(index);
    }

    private class FtpPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket inPacket = context.inPacket();
            Ethernet ethPacket = inPacket.parsed();

            if(ethPacket == null) {
                return;
            }

            if(!isFtpPacket(ethPacket)) {
                return;
            }

            log.info("Received FTP packet");
            IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
            Ip4Address destinationAddress = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());

            if(destinationAddress.equals(sharedAddress)) {
                OutboundPacket outPacket = context.outPacket();
                TrafficTreatment treatment = DefaultTrafficTreatment.builder(outPacket.treatment())
                                                                    .setIpDst(getNextHost())
                                                                    .build();
                packetService.emit(outPacket);
            }

        }
    }

    private boolean isFtpPacket(Ethernet ethPacket) {
        List<Integer> standardFtpPorts = Arrays.asList(20, 21);

        if (ethPacket.getEtherType() != Ethernet.TYPE_IPV4) {
            return false;
        }

        IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
        if(ipv4Packet.getProtocol() != (byte) 0x06) {
            return false;
        }

        TCP tcpPacket = (TCP) ipv4Packet.getPayload();
        int destinationPort = tcpPacket.getDestinationPort();
        if(standardFtpPorts.contains(destinationPort)) {
            return true;
        }
        return false;
    }

    private void requestIntercepts() {
        selector = DefaultTrafficSelector.builder()
                                         .matchEthType(Ethernet.TYPE_IPV4)
                                         .matchIPProtocol((byte) 0x06)
                                         .build();

        packetService.requestPackets(selector, packetPriority, appId); // TODO check with HIGH or MEDIUM
    }

    private void withdrawIntercepts() {
        packetService.cancelPackets(selector, packetPriority, appId);
    }

    @Override
    public Set<Class<?>> getClasses() {
        return getClasses(FtpWebResource.class);
    }

    @Path("/psik")
    private class FtpWebResource extends AbstractWebResource {

        @GET
        @Path("/shared-address")
        @Produces(MediaType.APPLICATION_JSON)
        public Response getSharedAddress() {
            return Response.ok().entity(sharedAddress.toString()).build();
        }

        @POST
        @Path("/shared-address/{address}")
        public Response setSharedAddress(@PathParam("address") String address) {
            setSharedAddress(address);
            return Response.ok().build();
        }

        @DELETE
        @Path("/shared-address")
        public Response deleteSharedAddress() {
            sharedAddress = null;
            return Response.ok().build();
        }

        @GET
        @Path("/servers")
        @Produces(MediaType.APPLICATION_JSON)
        public Response getServers() {
            return Response.ok().entity(hostsAssignedToSharedAddress).build();
        }

        @POST
        @Path("/servers/{address}")
        public Response addServer(@PathParam("address") String address) {
            hostsAssignedToSharedAddress.add(Ip4Address.valueOf(address));
            return Response.ok().build();
        }

        @DELETE
        @Path("/servers/{address}")
        public Response deleteServer(@PathParam("address") String address) {
            hostsAssignedToSharedAddress.remove(Ip4Address.valueOf(address));
            return Response.ok().build();
        }

        @GET
        @Path("/sessions")
        @Produces(MediaType.APPLICATION_JSON)
        public Response getSessions() {
            // TODO
            return Response.ok().build();
        }

    }
}
