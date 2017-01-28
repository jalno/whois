<?php
namespace packages\whois;
class moniker_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant',
            'admin' => 'Administrative ',
            'tech' => 'Technical ',
            'billing' => 'Billing ',
            'domain.name' => 'Domain Name:',
            'domain.nserver.' => 'Domain servers in listed order:',
            'domain.created' => 'Record created on: ',
            'domain.expires' => 'Domain Expires on: ',
            'domain.changed' => 'Database last updated on: '
        );

        return easy_parser($data_str, $items, 'ymd');
    }

}
