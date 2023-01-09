const request = require("supertest");
const cheerio = require("cheerio");
const db = require("../models/index");
const app = require("../app");

let server, agent;

function extractCsrfToken(res) {
  var $ = cheerio.load(res.text);
  return $("[name=_csrf]").val();
}

const login = async (agent, username, password) => {
  let res = await agent.get("/login");
  let csrfToken = extractCsrfToken(res);
  res = await agent.post("/session").send({
    email: username,
    password: password,
    _csrf: csrfToken,
  });
};

describe("Online Voting Application", function () {
  beforeAll(async () => {
    await db.sequelize.sync({ force: true });
    server = app.listen(4040, () => {});
    agent = request.agent(server);
  });

  afterAll(async () => {
    try {
      await db.sequelize.close();
      await server.close();
    } catch (error) {
      console.log(error);
    }
  });

  test("Sign Up", async () => {
    let res = await agent.get("/signup");
    const csrfToken = extractCsrfToken(res);
    res = await agent.post("/admin").send({
      firstName: "sowmya",
      lastName: "volladapu",
      email: "volladapusowmya2002@gmail.com",
      password: "12345678",
      _csrf: csrfToken,
    });
    expect(res.statusCode).toBe(302);
  });

  test("Sign In", async () => {
    const agent = request.agent(server);
    let res = await agent.get("/elections");
    expect(res.statusCode).toBe(302);
    await login(agent, "volladapusowmya2002@gmail.com", "12345678");
    res = await agent.get("/elections");
    expect(res.statusCode).toBe(200);
  });

  test("Sign Out", async () => {
    let res = await agent.get("/elections");
    expect(res.statusCode).toBe(200);
    res = await agent.get("/signout");
    expect(res.statusCode).toBe(302);
    res = await agent.get("/elections");
    expect(res.statusCode).toBe(302);
  });

  test("Creating election", async () => {
    const agent = request.agent(server);
    await login(agent, "skreddy@gmail.com", "skreddy");
    const res = await agent.get("/electionpage/addelection");
    const csrfToken = extractCsrfToken(res);
    const response = await agent.post("/electionpage").send({
      electionName: "election",
      publicurl: "election",
      _csrf: csrfToken,
    });
    expect(response.statusCode).toBe(302);
  });

  test("Add a question", async () => {
    const agent = request.agent(server);
    await login(agent, "volladapusowmya2002@gmail.com", "12345678");
  
    //create new election
    // let res = await agent.get("/elections/create");
    // let csrfToken = extractCsrfToken(res);
    // await agent.post("/elections").send({
    //   electionName: "Test election",
    //   urlString: "test2",
    //   _csrf: csrfToken,
    // });
    // const groupedElectionsResponse = await agent
    //   .get("/elections")
    //   .set("Accept", "application/json");
    // const parsedGroupedResponse = JSON.parse(groupedElectionsResponse.text);
    // const electionCount = parsedGroupedResponse.elections.length;
    // const latestElection = parsedGroupedResponse.elections[electionCount - 1];
    // test("Creating election", async () => {
    //   const agent = request.agent(server);
    //   await login(agent, "volladapusowmya2002@gmail.com", "12345678");
    //   const res = await agent.get("/electionpage/addelection");
    //   const csrfToken = extractCsrfToken(res);
    //   const response = await agent.post("/electionpage").send({
    //     electionName: "election",
    //     publicurl: "election",
    //     _csrf: csrfToken,
    //   });
    //   expect(response.statusCode).toBe(302);
    // });
  //   //add a question
    res = await agent.get(`/elections/${latestElection.id}/questions/create`);
    csrfToken = extractCsrfToken(res);
    let response = await agent
      .post(`/elections/${latestElection.id}/questions/create`)
      .send({
        question: "Test question",
        description: "Test description",
        _csrf: csrfToken,
      });
    expect(response.statusCode).toBe(302);
  });

  test("Delete a question", async () => {
    const agent = request.agent(server);
    await login(agent, "volladapusowmya2002@gmail.com", "12345678");

    //create new election
    let res = await agent.get("/elections/create");
    let csrfToken = extractCsrfToken(res);
    await agent.post("/elections").send({
      electionName: "Test election",
      urlString: "test3",
      _csrf: csrfToken,
    });
    const groupedElectionsResponse = await agent
      .get("/elections")
      .set("Accept", "application/json");
    const parsedGroupedElectionsResponse = JSON.parse(
      groupedElectionsResponse.text
    );
    const electionCount = parsedGroupedElectionsResponse.elections.length;
    const latestElection =
      parsedGroupedElectionsResponse.elections[electionCount - 1];

    //add a question
    // res = await agent.get(`/elections/${latestElection.id}/questions/create`);
    // csrfToken = extractCsrfToken(res);
    // await agent.post(`/elections/${latestElection.id}/questions/create`).send({
    //   question: "Test question 1",
    //   description: "Test description 1",
    //   _csrf: csrfToken,
    // });

    res = await agent.get(`/elections/${latestElection.id}/questions/create`);
    csrfToken = extractCsrfToken(res);
    await agent.post(`/elections/${latestElection.id}/questions/create`).send({
      question: "Test question 2",
      description: "Test description 2",
      _csrf: csrfToken,
    });

    const groupedQuestionsResponse = await agent
      .get(`/elections/${latestElection.id}/questions`)
      .set("Accept", "application/json");
    const parsedQuestionsGroupedResponse = JSON.parse(
      groupedQuestionsResponse.text
    );
    const questionCount = parsedQuestionsGroupedResponse.questions.length;
    const latestQuestion =
      parsedQuestionsGroupedResponse.questions[questionCount - 1];

    res = await agent.get(`/elections/${latestElection.id}/questions`);
    csrfToken = extractCsrfToken(res);
    const deleteResponse = await agent
      .delete(`/elections/${latestElection.id}/questions/${latestQuestion.id}`)
      .send({
        _csrf: csrfToken,
      });
    const parsedDeleteResponse = JSON.parse(deleteResponse.text).success;
    expect(parsedDeleteResponse).toBe(true);

    res = await agent.get(`/elections/${latestElection.id}/questions`);
    csrfToken = extractCsrfToken(res);

    const deleteResponse2 = await agent
      .delete(`/elections/${latestElection.id}/questions/${latestQuestion.id}`)
      .send({
        _csrf: csrfToken,
      });
    const parsedDeleteResponse2 = JSON.parse(deleteResponse2.text).success;
    expect(parsedDeleteResponse2).toBe(false);
  });

  test("Update a question", async () => {
    const agent = request.agent(server);
    await login(agent, "volladapusowmya2002@gmail.com", "12345678");

    //create new election
    let res = await agent.get("/elections/create");
    let csrfToken = extractCsrfToken(res);
    await agent.post("/elections").send({
      electionName: "Test election",
      urlString: "test4",
      _csrf: csrfToken,
    });
    const groupedElectionsResponse = await agent
      .get("/elections")
      .set("Accept", "application/json");
    const parsedGroupedElectionsResponse = JSON.parse(
      groupedElectionsResponse.text
    );
    const electionCount = parsedGroupedElectionsResponse.elections.length;
    const latestElection =
      parsedGroupedElectionsResponse.elections[electionCount - 1];

    //add a question
    res = await agent.get(`/elections/${latestElection.id}/questions/create`);
    csrfToken = extractCsrfToken(res);
    await agent.post(`/elections/${latestElection.id}/questions/create`).send({
      question: "Test question 1",
      description: "Test description 1",
      _csrf: csrfToken,
    });

    const groupedQuestionsResponse = await agent
      .get(`/elections/${latestElection.id}/questions`)
      .set("Accept", "application/json");
    const parsedQuestionsGroupedResponse = JSON.parse(
      groupedQuestionsResponse.text
    );
    const questionCount = parsedQuestionsGroupedResponse.questions.length;
    const latestQuestion =
      parsedQuestionsGroupedResponse.questions[questionCount - 1];

    res = await agent.get(
      `/elections/${latestElection.id}/questions/${latestQuestion.id}/edit`
    );
    csrfToken = extractCsrfToken(res);
    res = await agent.put(`/questions/${latestQuestion.id}/edit`).send({
      _csrf: csrfToken,
      question: "123",
      description: "456",
    });
    expect(res.statusCode).toBe(200);
  });
  
  test("Add an option", async () => {
    const agent = request.agent(server);
    await login(agent, "volladapusowmya2002@gmail.com", "12345678");

    //create new election
    let res = await agent.get("/elections/create");
    let csrfToken = extractCsrfToken(res);
    await agent.post("/elections").send({
      electionName: "Test election",
      urlString: "test5",
      _csrf: csrfToken,
    });
    const groupedElectionsResponse = await agent
      .get("/elections")
      .set("Accept", "application/json");
    const parsedGroupedResponse = JSON.parse(groupedElectionsResponse.text);
    const electionCount = parsedGroupedResponse.elections.length;
    const latestElection = parsedGroupedResponse.elections[electionCount - 1];

    //add a question
    res = await agent.get(`/elections/${latestElection.id}/questions/create`);
    csrfToken = extractCsrfToken(res);
    await agent.post(`/elections/${latestElection.id}/questions/create`).send({
      question: "Test question",
      description: "Test description",
      _csrf: csrfToken,
    });

    const groupedQuestionsResponse = await agent
      .get(`/elections/${latestElection.id}/questions`)
      .set("Accept", "application/json");
    const parsedQuestionsGroupedResponse = JSON.parse(
      groupedQuestionsResponse.text
    );
    const questionCount = parsedQuestionsGroupedResponse.questions.length;
    const latestQuestion =
      parsedQuestionsGroupedResponse.questions[questionCount - 1];

    res = await agent.get(
      `/elections/${latestElection.id}/questions/${latestQuestion.id}`
    );
    csrfToken = extractCsrfToken(res);

    res = await agent
      .post(`/elections/${latestElection.id}/questions/${latestQuestion.id}`)
      .send({
        _csrf: csrfToken,
        option: "Test option",
      });
    expect(res.statusCode).toBe(302);
  });

  test("Delete a option", async () => {
    const agent = request.agent(server);
    await login(agent, "volladapusowmya2002@gmail.com", "12345678");

    //create new election
    let res = await agent.get("/elections/create");
    let csrfToken = extractCsrfToken(res);
    await agent.post("/elections").send({
      electionName: "Test election",
      urlString: "test6",
      _csrf: csrfToken,
    });
    const groupedElectionsResponse = await agent
      .get("/elections")
      .set("Accept", "application/json");
    const parsedGroupedElectionsResponse = JSON.parse(
      groupedElectionsResponse.text
    );
    const electionCount = parsedGroupedElectionsResponse.elections.length;
    const latestElection =
      parsedGroupedElectionsResponse.elections[electionCount - 1];

 
  //   //can edit questions while election is not running
    res = await agent.get(`/elections/${latestElection.id}/questions`);
    expect(res.statusCode).toBe(200);

    res = await agent.get(`/elections/${latestElection.id}/preview`);
    csrfToken = extractCsrfToken(res);
    res = await agent.put(`/elections/${latestElection.id}/launch`).send({
      _csrf: csrfToken,
    });
    const launchedElectionRes = JSON.parse(res.text);
    expect(launchedElectionRes[1][0].running).toBe(true);

   //cannot edit questions while election is running
    res = await agent.get(`/elections/${latestElection.id}/questions`);
    expect(res.statusCode).toBe(302);
  });
});