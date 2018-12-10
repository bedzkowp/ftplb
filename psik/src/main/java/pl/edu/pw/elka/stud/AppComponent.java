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
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.*;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.*;
import org.onosproject.net.packet.*;
import org.onosproject.net.proxyarp.ProxyArpStoreDelegate;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.rest.AbstractWebResource;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.ws.rs.*;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.nio.ByteBuffer;
import java.util.*;

// TODO refactor, rename variables

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

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

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ProxyArpStoreDelegate proxyArpStoreDelegate;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    private FtpPacketProcessor ftpPacketProcessor = new FtpPacketProcessor();
    private PacketPriority packetPriority = PacketPriority.REACTIVE;

    private ApplicationId appId;
    private TrafficSelector selector;

    private Ip4Address sharedAddress;
    private List<Ip4Address> hostsAssignedToSharedAddress = new ArrayList<>();
    private Map<Ip4Address, Ip4Address> activeSessionsHostToServer = new HashMap<>();
    private Map<Ip4Address, List<Ip4Address>> hostsWithActiveFtpSessionsAssignedToOldSharedAddresses;
    private Random random = new Random();

    @Activate
    protected void activate() {
        log.info("Activating PSIK app");
        appId = coreService.registerApplication("pl.edu.pw.elka.stud.psik");
        packetService.addProcessor(ftpPacketProcessor, PacketProcessor.director(3)); // TODO check priority
        requestIntercepts();
        loadInitialConfig();

        log.info("Started: " + appId.name());
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(ftpPacketProcessor);
        ftpPacketProcessor = null;
        withdrawIntercepts();

        // TODO drop all flows installed by this app
        log.info("Stopped: " + appId.name());
    }

    private void loadInitialConfig() {
        // TODO load from REST and check for correctness
        sharedAddress = Ip4Address.valueOf("10.0.1.10");
        Ip4Address serverAddress1 = Ip4Address.valueOf("10.0.1.1");
        Ip4Address serverAddress2 = Ip4Address.valueOf("10.0.1.2");
        Ip4Address serverAddress3 = Ip4Address.valueOf("10.0.1.3");
        hostsAssignedToSharedAddress.add(serverAddress1);
        hostsAssignedToSharedAddress.add(serverAddress2);
        hostsAssignedToSharedAddress.add(serverAddress3);
    }

    private Optional<Ip4Address> getNextServerIp() {
        int index = random.nextInt(hostsAssignedToSharedAddress.size());
        return Optional.ofNullable(Ip4Address.valueOf("10.0.1.1"));
        // TODO get from list
        // return hostsAssignedToSharedAddress.get(index);
    }

    private class FtpPacketProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            InboundPacket inPacket = context.inPacket();
            Ethernet ethPacket = inPacket.parsed();
            ConnectPoint srcConnectPoint = inPacket.receivedFrom();

            if(ethPacket == null) {
                return;
            }

            log.info("processing any packet");

            switch (EthType.EtherType.lookup(ethPacket.getEtherType())) {
                case ARP:
                    log.info("Processing ARP packet");
                    ARP arpPacket = (ARP) ethPacket.getPayload();
                    Ip4Address targetAddress = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());

                    if(arpPacket.getOpCode() == ARP.OP_REQUEST &&
                        targetAddress.equals(sharedAddress)) {
                        log.info("Processing my packet");
                        Optional<Ip4Address> nextServerIpOptional = getNextServerIp(); // TODO throw exception
                        if(nextServerIpOptional.isPresent()) {
                            Ip4Address nextServerIp = nextServerIpOptional.get();
                            Set<Host> hosts = hostService.getHostsByIp(nextServerIp);
                            if(hosts.size() == 0) {
                               log.info("hosts size is 0");
                                return; // TODO throw exception
                            } else if(hosts.size() > 1) {
                                log.info("hosts size is > 1");
                                return; // TODO throw exception
                            } else {
                                MacAddress nextServerMac = hosts.iterator().next().mac();

                                Ethernet arpReply = ARP.buildArpReply(targetAddress, nextServerMac, ethPacket);

                                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                                        .setOutput(srcConnectPoint.port())
                                        .build();
                                log.info("Emiting to device and port " + srcConnectPoint.deviceId() + " " +
                                        srcConnectPoint.port());
                                packetService.emit(new DefaultOutboundPacket(
                                        srcConnectPoint.deviceId(),
                                        treatment,
                                        ByteBuffer.wrap(arpReply.serialize())));
                            }
                        } else {
                            log.info("Next server is optional");
                            return;
                        }
                    }
                    break;
            }

////            log.info("PSIK: Packet received from: " + inPacket.receivedFrom().deviceId());
////
////            if (ethPacket.getEtherType() == Ethernet.TYPE_ARP) {
////                ARP arpPacket = (ARP) ethPacket.getPayload();
////                log.info("PSIK: ARP packet: " + arpPacket);
////
////                Ip4Address targetAddress = Ip4Address.valueOf(arpPacket.getTargetProtocolAddress());
////                Ip4Address sourceAddress = Ip4Address.valueOf(arpPacket.getSenderProtocolAddress());
////                MacAddress srcMacAddress = MacAddress.valueOf(arpPacket.getSenderHardwareAddress());
////                log.info("PSIK: ARP target protocol address " + targetAddress);
////
////                if (targetAddress.equals(sharedAddress)) {
////                    Ip4Address newTargetAddress = activeSessionsHostToServer.getOrDefault(sourceAddress, getNextServerIp());
////                    activeSessionsHostToServer.put(sourceAddress, newTargetAddress);
////                    // arpPacket.setTargetProtocolAddress(newTargetAddress.toInt());
////                    // ethPacket.setPayload(arpPacket);
////                    // context.send();
////
////                    if (context.inPacket().receivedFrom().deviceId().equals(DeviceId.deviceId("of:0000000000000001"))) {
////                        DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
////                        int port = 1;
////                        String connectionP = deviceId + "/" + port;
////                        proxyArpStoreDelegate.emitResponse(ConnectPoint.deviceConnectPoint(connectionP),
////                                ByteBuffer.wrap(ARP.buildArpReply(sourceAddress, srcMacAddress, ethPacket).serialize()));
////                        log.info("PSIK: Proxy delegate");
////                    }
////
////                    log.info("PSIK: Sent changed ARP packet " + ethPacket);
////                }
////                return;
////            }
//
//            if (ethPacket.getEtherType() != Ethernet.TYPE_IPV4) {
//                return;
//            }
//
//            log.info("Got IP v4 packet");
//
//            IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
//            if (!Ip4Address.valueOf(ipv4Packet.getDestinationAddress()).equals(sharedAddress)) {
//                return;
//            }
//
//
//            // log.info("PSIK: Received Ethernet packet");
//
//            if(!isFtpPacket(ethPacket)) {
//                return;
//            }
//
//            // IPv4 ipv4Packet = (IPv4) ethPacket.getPayload();
//            Ip4Address destinationAddress = Ip4Address.valueOf(ipv4Packet.getDestinationAddress());
//
//            if(destinationAddress.equals(sharedAddress)) {
//                log.info("PSIK: Received packet for shared address");
//
//                // TODO handle packet and install flows
//                Ip4Address sourceAddress = Ip4Address.valueOf(ipv4Packet.getSourceAddress());
//                Ip4Address newServerAddress = activeSessionsHostToServer.get(sourceAddress);
//
//                if (newServerAddress == null) {
//                    newServerAddress = getNextServerIp();
//                    activeSessionsHostToServer.put(sourceAddress, newServerAddress);
//                }
//
//                log.info("PSIK: Next server address for host: " + sourceAddress + " is: " + newServerAddress);
//                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
//                        .setIpDst(newServerAddress)
//                        .build();
//                OutboundPacket outPacket = new DefaultOutboundPacket(inPacket.receivedFrom().deviceId(),
//                       treatment, ByteBuffer.wrap(ethPacket.serialize()));
//                packetService.emit(outPacket);
//                log.info("PSIK: emited packet: " + outPacket);
//            }
//
        }
    }

    private void installRule(PacketContext context) {
        log.info("Installing rule");
        TrafficSelector selector = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(sharedAddress.toIpPrefix())
                .build();

        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
//                .setIpDst(getNextServerIp())
                .setOutput(PortNumber.portNumber(3))
                .build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selector)
                .withTreatment(treatment)
                .withPriority(100)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                //.makeTemporary(flowTimeout)
                .add();

//        flowObjectiveService.forward(DeviceId.deviceId("of:0000000000000002"),
//                forwardingObjective);

        HostStore hostStore;
        log.info("FLow installed");
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
            log.info("PSIK: Received FTP packet: " + tcpPacket);
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

//    @Override
//    public Set<Class<?>> getClasses() {
//        return getClasses(FtpWebResource.class);
//    }

    @Path("/psik")
    private class FtpWebResource extends AbstractWebResource {

        @GET
        @Path("/shared-address")
        @Produces(MediaType.APPLICATION_JSON)
        public Response getSharedAddress() {
            log.info("REST getSharedAddress");
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
