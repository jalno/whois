<?php
namespace packages\whois;
class domaindiscover_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative Contact',
            'tech' => 'Technical Contact',
            'zone' => 'Zone Contact',
            'domain.name' => 'Domain Name:',
            'domain.changed' => 'Last updated on',
            'domain.created' => 'Domain created on',
            'domain.expires' => 'Domain expires on'
        );

        return easy_parser($data_str, $items, 'dmy', array(), false, true);
    }

}
