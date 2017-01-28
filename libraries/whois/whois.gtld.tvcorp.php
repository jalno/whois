<?php
namespace packages\whois;
class tvcorp_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant',
            'admin' => 'Admin',
            'tech' => 'Technical',
            'billing' => 'Billing',
            'domain.nserver.' => 'Domain servers:',
            'domain.created' => 'Record created on',
            'domain.expires' => 'Record expires on'
        );

        return easy_parser($data_str, $items, 'mdy');
    }

}
