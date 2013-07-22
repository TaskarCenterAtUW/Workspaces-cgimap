#ifndef WRITEABLE_PGSQL_SELECTION_HPP
#define WRITEABLE_PGSQL_SELECTION_HPP

#include "data_selection.hpp"
#include "backend/apidb/changeset.hpp"
#include "backend/apidb/cache.hpp"
#include <pqxx/pqxx>
#include <boost/program_options.hpp>

/**
 * a selection which operates against a writeable (i.e: non read-only
 * slave) PostgreSQL database, such as the rails_port database or
 * an osmosis imported database.
 */
class writeable_pgsql_selection
	: public data_selection {
public:
	 writeable_pgsql_selection(pqxx::connection &conn, cache<osm_id_t, changeset> &changeset_cache);
	 ~writeable_pgsql_selection();

	 void write_nodes(output_formatter &formatter);
	 void write_ways(output_formatter &formatter);
	 void write_relations(output_formatter &formatter);

	 int num_nodes();
	 int num_ways();
	 int num_relations();
	 visibility_t check_node_visibility(osm_id_t id);
	 visibility_t check_way_visibility(osm_id_t id);
	 visibility_t check_relation_visibility(osm_id_t id);

	 int select_nodes(const std::list<osm_id_t> &);
	 int select_ways(const std::list<osm_id_t> &);
	 int select_relations(const std::list<osm_id_t> &);
	 int select_nodes_from_bbox(const bbox &bounds, int max_nodes);
	 void select_nodes_from_relations();
	 void select_ways_from_nodes();
	 void select_ways_from_relations();
	 void select_relations_from_ways();
	 void select_nodes_from_way_nodes();
	 void select_relations_from_nodes();
	 void select_relations_from_relations();
  void select_relations_members_of_relations();

   /**
    * abstracts the creation of transactions for the writeable
    * data selection.
    */
   class factory
      : public data_selection::factory {
   public:
     factory(const boost::program_options::variables_map &);
     virtual ~factory();
     virtual boost::shared_ptr<data_selection> make_selection();

   private:
     pqxx::connection m_connection, m_cache_connection;
     pqxx::nontransaction m_cache_tx;
     cache<osm_id_t, changeset> m_cache;
   };

private:

   // the transaction in which the selection takes place. although 
   // this *is* read-only, it may create temporary tables.
   pqxx::work w;
   
  cache<osm_id_t, changeset> cc;

};

#endif /* WRITEABLE_PGSQL_SELECTION_HPP */
