<?php
namespace packages\whois;
class srsplus_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative',
            'tech' => 'Technical',
            'billing' => 'Billing',
            'domain.name' => 'Domain Name:',
            'domain.nserver' => 'Domain servers:',
            'domain.created' => 'Record created on',
            'domain.expires' => 'Record expires on'
        );

        return easy_parser($data_str, $items, 'ymd', array(), true, true);
    }

}
