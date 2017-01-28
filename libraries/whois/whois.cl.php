<?php
namespace packages\whois;
class cl_handler {

    function parse($data_str, $query) {
        $items = array(
            'admin' => '(Administrative Contact)',
            'tech' => 'Contacto Técnico (Technical Contact):',
            'domain.nserver' => 'Servidores de nombre (Domain servers):',
            'domain.changed' => '(Database last updated on):'
        );

        $trans = array(
            'organización:' => 'organization',
            'nombre      :' => 'name');

        $r = array();
        $r['regrinfo'] = easy_parser($data_str['rawdata'], $items, 'd-m-y', $trans);
        $r['regyinfo'] = array(
            'referrer' => 'http://www.nic.cl',
            'registrar' => 'NIC Chile'
        );
        return $r;
    }

}
