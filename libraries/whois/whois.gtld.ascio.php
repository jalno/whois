<?php
namespace packages\whois;
class ascio_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative ',
            'tech' => 'Technical ',
            'domain.name' => 'Domain name:',
            'domain.nserver.' => 'Domain servers in listed order:',
            'domain.created' => 'Record created:',
            'domain.expires' => 'Record expires:',
            'domain.changed' => 'Record last updated:'
        );

        return easy_parser($data_str, $items, 'ymd', array(), false, true);
    }

}
