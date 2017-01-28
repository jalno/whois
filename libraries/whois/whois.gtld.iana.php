<?php
namespace packages\whois;
class iana_handler {

    function parse($data_str, $query) {
        $items = array(
            'admin' => 'contact:      administrative',
            'tech' => 'contact:      technical',
            'domain.nserver.' => 'nserver:',
            'domain.created' => 'created:',
            'domain.changed' => 'changed:',
            'domain.source' => 'source:',
            'domain.name' => 'domain:',
            'disclaimer.' => '% '
        );

        return easy_parser($data_str, $items, 'Ymd', array(), false, false, 'owner');
    }

}
