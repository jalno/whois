<?php
namespace packages\whois;
class networksolutions_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative Contact',
            'tech' => 'Technical Contact',
            'domain.name' => 'Domain Name:',
            'domain.nserver.' => 'Domain servers in listed order:',
            'domain.created' => 'Record created on',
            'domain.expires' => 'Record expires on'
        );

        return easy_parser($data_str, $items, 'dmy', array(), true, true);
    }

}
