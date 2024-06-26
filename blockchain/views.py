from django.shortcuts import render, redirect
from django.conf import settings
from .node import Node
BLOCKCHAIN_NETWORK = settings.BLOCKCHAIN_NETWORK

# data_node_list = Node(hostname=BLOCKCHAIN_NETWORK["FIRST_KNOW_NODE_HOSTNAME"]).known_node_request()
# BLOCKCHAIN_NETWORK["DATA_NODES"] = data_node_list


def get_data_node(request):
    data_node_list = Node(hostname=BLOCKCHAIN_NETWORK["FIRST_KNOW_NODE_HOSTNAME"]).known_node_request()
    BLOCKCHAIN_NETWORK["DATA_NODES"] = data_node_list
    return redirect(request.META.get('HTTP_REFERER'))

