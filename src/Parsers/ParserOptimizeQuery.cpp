#include <Parsers/ParserOptimizeQuery.h>
#include <Parsers/ParserPartition.h>
#include <Parsers/CommonParsers.h>

#include <Parsers/ASTOptimizeQuery.h>
#include <Parsers/ExpressionListParsers.h>


namespace DB
{

bool ParserOptimizeQueryColumnsSpecification::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{
    // Do not allow APPLY and REPLACE transformers.
    // Since we use Columns Transformers only to get list of columns,
    // we can't actually modify content of the columns for deduplication.
    const auto allowed_transformers = ParserColumnsTransformers::ColumnTransformers{ParserColumnsTransformers::ColumnTransformer::EXCEPT};

    return ParserColumnsMatcher(allowed_transformers).parse(pos, node, expected)
        || ParserAsterisk(allowed_transformers).parse(pos, node, expected)
        || ParserIdentifier(false).parse(pos, node, expected);
}


bool ParserOptimizeQuery::parseImpl(Pos & pos, ASTPtr & node, Expected & expected)
{
    ParserKeyword s_optimize_table(Keyword::OPTIMIZE_TABLE);
    ParserKeyword s_partition(Keyword::PARTITION);
    ParserKeyword s_final(Keyword::FINAL);
    ParserKeyword s_force(Keyword::FORCE);
    ParserKeyword s_deduplicate(Keyword::DEDUPLICATE);
    ParserKeyword s_cleanup(Keyword::CLEANUP);
    ParserKeyword s_by(Keyword::BY);
    ParserToken s_dot(TokenType::Dot);
    ParserIdentifier name_p(true);
    ParserPartition partition_p;

    ASTPtr database;
    ASTPtr table;
    ASTPtr partition;
    bool final = false;
    bool deduplicate = false;
    bool cleanup = false;
    String cluster_str;

    if (!s_optimize_table.ignore(pos, expected))
        return false;

    if (!name_p.parse(pos, table, expected))
        return false;

    if (s_dot.ignore(pos, expected))
    {
        database = table;
        if (!name_p.parse(pos, table, expected))
            return false;
    }

    if (ParserKeyword{Keyword::ON}.ignore(pos, expected) && !ASTQueryWithOnCluster::parse(pos, cluster_str, expected))
        return false;

    if (s_partition.ignore(pos, expected))
    {
        if (!partition_p.parse(pos, partition, expected))
            return false;
    }

    if (s_final.ignore(pos, expected) || s_force.ignore(pos, expected))
        final = true;

    if (s_deduplicate.ignore(pos, expected))
        deduplicate = true;

    if (s_cleanup.ignore(pos, expected))
        cleanup = true;

    ASTPtr deduplicate_by_columns;
    if (deduplicate && s_by.ignore(pos, expected))
    {
        if (!ParserList(std::make_unique<ParserOptimizeQueryColumnsSpecification>(), std::make_unique<ParserToken>(TokenType::Comma), false)
                .parse(pos, deduplicate_by_columns, expected))
            return false;
    }

    auto query = std::make_shared<ASTOptimizeQuery>();
    node = query;

    query->cluster = cluster_str;
    if ((query->partition = partition))
        query->children.push_back(partition);
    query->final = final;
    query->deduplicate = deduplicate;
    query->deduplicate_by_columns = deduplicate_by_columns;
    query->cleanup = cleanup;
    query->database = database;
    query->table = table;

    if (database)
        query->children.push_back(database);

    if (table)
        query->children.push_back(table);

    return true;
}


}
