/*
 * Copyright 2019-present Open Networking Foundation
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
package pl.edu.pw;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onlab.packet.Ip4Address;
import org.onosproject.rest.AbstractWebResource;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Map;

/**
 * Sample web resource.
 */
@Path("")
public class AppWebResource extends AbstractWebResource {

    protected FtpApp ftpApp = get(FtpApp.class);

    @GET
    @Path("/shared-address")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSharedAddress() {
        ObjectNode node = mapper().createObjectNode();
        Ip4Address sharedAddress = ftpApp.getSharedAddress();
        if (sharedAddress != null) {
            node.put("sharedAddress", sharedAddress.toString());
        }
        return Response.ok(node).build();
    }

    @PUT
    @Path("/shared-address/{address}")
    public Response setSharedAddress(@PathParam("address") String address) {
        Ip4Address newSharedAddress = Ip4Address.valueOf(address);
        try {
            ftpApp.validateSharedIpAddress(newSharedAddress);
        } catch (FtpApp.ConflictException e) {
            return Response.status(Response.Status.CONFLICT).entity(e.getMessage()).build();
        } catch (FtpApp.NotFoundException e) {
            return Response.status(Response.Status.NOT_FOUND).entity(e.getMessage()).build();
        }
        ftpApp.setSharedAddress(newSharedAddress);
        return Response.ok().build();
    }

    @DELETE
    @Path("/shared-address")
    public Response deleteSharedAddress() {
        ftpApp.setSharedAddress(null);
        return Response.ok().build();
    }

    @GET
    @Path("/servers")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getServers() {
        ObjectNode node = mapper().createObjectNode();
        ArrayNode arrayNode = node.putArray("servers");
        for (Ip4Address ip : ftpApp.getServersAssignedToSharedAddress()) {
            arrayNode.add(ip.toString());
        }
        return Response.ok(node).build();
    }

    @PUT
    @Path("/servers/{address}")
    public Response assignServer(@PathParam("address") String address) {
        Ip4Address serverIp = Ip4Address.valueOf(address);
        try {
            ftpApp.validateFtpServerAddress(serverIp);
        } catch (FtpApp.ConflictException e) {
            return Response.status(Response.Status.CONFLICT).entity(e.getMessage()).build();
        } catch (FtpApp.NotFoundException e) {
            return Response.status(Response.Status.NOT_FOUND).entity(e.getMessage()).build();
        }
        ftpApp.assignServerToSharedAddress(serverIp);
        return Response.ok().build();
    }

    @DELETE
    @Path("/servers/{address}")
    public Response deleteServer(@PathParam("address") String address) {
        ftpApp.unassignServerFromSharedAddress(Ip4Address.valueOf(address));
        return Response.ok().build();
    }

    @GET
    @Path("/sessions")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSessions() {
        ObjectNode node = mapper().createObjectNode();
        ArrayNode arrayNode = node.putArray("sessions");
        Map<FtpApp.FtpSessionKey, Ip4Address> sessions = ftpApp.getActiveFtpSessions();

        for (FtpApp.FtpSessionKey key : sessions.keySet()) {
            ObjectNode sessionNode = mapper().createObjectNode();
            sessionNode.put("clientIp", key.getClientIp().toString());
            sessionNode.put("clientPort", key.getClientPort().toString());
            sessionNode.put("sharedIp", key.getSharedIp().toString());
            sessionNode.put("serverIp", sessions.get(key).toString());
            arrayNode.add(sessionNode);
        }
        return Response.ok(node).build();
    }
}
