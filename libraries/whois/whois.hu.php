<?php
namespace packages\whois;
class hu_handler {

    function parse($data_str, $query) {
        $items = array(
            'domain:' => 'domain.name',
            'record created:' => 'domain.created'
        );

        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], $items, 'ymd');

        if (isset($r['regrinfo']['domain']))
            $r['regrinfo']['registered'] = 'yes';
        else
            $r['regrinfo']['registered'] = 'no';

        $r['regyinfo'] = array('referrer' => 'http://www.nic.hu', 'registrar' => 'HUNIC');
        return $r;
    }

}
