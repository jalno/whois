<?php
namespace packages\whois;
class biz_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], array(), '-md--y');
        $r['regyinfo'] = array(
            'referrer' => 'http://www.neulevel.biz',
            'registrar' => 'NEULEVEL'
        );
        return $r;
    }

}
