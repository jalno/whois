<?php
namespace packages\whois;
/* TODO:
   - whois - converter para http://domaininfo.com/idn_conversion.asp punnycode antes de efectuar a pesquisa
   - o punnycode deveria fazer parte dos resultados fazer parte dos resultados!
*/
class pt_handler
	{
	function parse($data, $query)
		{
		$items = array(
					'domain.name' 		=> ' / Domain Name:',
					'domain.created' 	=> 'Data de registo / Creation Date (dd/mm/yyyy):',
					'domain.nserver.' 	=> 'Nameserver:',
					'domain.status'	 	=> 'Estado / Status:',
					'owner'				=> 'Titular / Registrant',
					'billing'			=> 'Entidade Gestora / Billing Contact',
					'admin'				=> 'Responsável Administrativo / Admin Contact',
					'tech'				=> 'Responsável Técnico / Tech Contact',
					'#'					=> 'Nameserver Information'
					);

		$r['regrinfo'] = get_blocks($data['rawdata'], $items);

		if (empty($r['regrinfo']['domain']['name']))
			{
			print_r($r['regrinfo']);
			$r['regrinfo']['registered'] = 'no';
			return $r;
			}

		$r['regrinfo']['domain']['created'] = get_date($r['regrinfo']['domain']['created'], 'dmy');

		if ($r['regrinfo']['domain']['status'] == 'ACTIVE')
			{
			$r['regrinfo'] = get_contacts($r['regrinfo']);
			$r['regrinfo']['registered'] = 'yes';
			}
		else
			$r['regrinfo']['registered'] = 'no';

		$r['regyinfo'] = array(
			'referrer' => 'http://www.fccn.pt',
			'registrar' => 'FCCN'
			);

		return $r;
		}
	}
?>
