<?php
namespace packages\whois;
class gandi_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'owner-c',
            'admin' => 'admin-c',
            'tech' => 'tech-c',
            'billing' => 'bill-c'
        );

        $trans = array(
            'nic-hdl:' => 'handle',
            'person:' => 'name',
            'zipcode:' => 'address.pcode',
            'city:' => 'address.city',
            'lastupdated:' => 'changed',
            'owner-name:' => ''
        );

        return easy_parser($data_str, $items, 'dmy', $trans);
    }

}
