<?php
namespace packages\whois;
class aero_handler {

    function parse($data_str, $query) {
        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], array(), 'ymd');
        $r['regyinfo'] = array(
            'referrer' => 'http://www.nic.aero',
            'registrar' => 'Societe Internationale de Telecommunications Aeronautiques SC'
        );
        return $r;
    }

}
