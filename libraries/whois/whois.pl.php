<?php
namespace packages\whois;
class pl_handler {

    function parse($data_str, $query) {
        $items = array(
            'domain.created' => 'created:',
            'domain.changed' => 'last modified:',
            'domain.sponsor' => 'REGISTRAR:',
            '#' => 'WHOIS displays data with a delay not exceeding 15 minutes in relation to the .pl Registry system'
        );

        $r = array();
        $r['regrinfo'] = easy_parser($data_str['rawdata'], $items, 'ymd');

        $r['regyinfo'] = array(
            'referrer' => 'http://www.dns.pl/english/index.html',
            'registrar' => 'NASK'
        );
        return $r;
    }

}
