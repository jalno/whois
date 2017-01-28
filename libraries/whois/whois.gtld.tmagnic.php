<?php
namespace packages\whois;
class tmagnic_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Owner Contact:',
            'admin' => 'Admin Contact',
            'tech' => 'Technical Contact',
            'domain.name' => 'Domain Name:',
            'domain.nserver.' => 'Domain servers in listed order:',
            'domain.expires' => 'Record expires on: ',
            'domain.changed' => 'Record last updated on: ',
            '' => 'Zone Contact',
            '#' => 'Punycode Name:'
        );

        return easy_parser($data_str, $items, 'ymd', array(), false, true);
    }

}
