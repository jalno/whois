<?php
namespace packages\whois;
class rwhois_handler {

    function parse($data_str, $query) {
        $items = array(
            'network:Organization-Name:' => 'owner.name',
            'network:Organization;I:' => 'owner.organization',
            'network:Organization-City:' => 'owner.address.city',
            'network:Organization-Zip:' => 'owner.address.pcode',
            'network:Organization-Country:' => 'owner.address.country',
            'network:IP-Network-Block:' => 'network.inetnum',
            'network:IP-Network:' => 'network.inetnum',
            'network:Network-Name:' => 'network.name',
            'network:ID:' => 'network.handle',
            'network:Created:' => 'network.created',
            'network:Updated:' => 'network.changed',
            'network:Tech-Contact;I:' => 'tech.email',
            'network:Admin-Contact;I:' => 'admin.email'
        );

        $res = generic_parser_b($data_str, $items, 'Ymd', false);
        if (isset($res['disclaimer']))
            unset($res['disclaimer']);
        return array('regrinfo' => $res);
    }

}
